import select
import socket
import time
from typing import Optional
from . import config
from . import logger
from . import ai_engine
from . import db
from . import analyzer
HONEYPOT_LOGGER = logger.get_logger()
MITRE = analyzer.get_mitre()


class AIShellHandler:

    def __init__(self, channel, client_ip: str, username: str = 'root'):
        self.channel = channel
        self.client_ip = client_ip
        self.username = username
        self.session_id = f"{client_ip}:{int(time.time())}"
        self.running = True
        self.engine = ai_engine.get_engine()

    def start(self):
        session = self.engine.get_or_create_session(self.session_id)
        session.username = self.username

        self.channel.send(config.SHELL_BANNER)
        self._interact()

    def _interact(self):
        while self.running and not self.channel.closed:
            try:
                r, _, _ = select.select([self.channel], [], [], 0.5)
                if not r:
                    continue

                data = self.channel.recv(1024)
                if not data:
                    break

                try:
                    raw = data.decode('utf-8', errors='ignore')
                except Exception:
                    raw = str(data)

                raw = raw.replace('\r\n', '\n').replace('\r', '\n')
                for line in raw.split('\n'):
                    line = line.strip()
                    if not line:
                        if not self.running or self.channel.closed:
                            return
                        self._send_prompt()
                        continue

                    cmd_lower = line.strip().lower()
                    if cmd_lower in ('exit', 'quit', 'logout'):
                        self.channel.send('logout\r\n')
                        self.running = False
                        self._cleanup()
                        try:
                            self.channel.close()
                        except Exception:
                            pass
                        return

                    if cmd_lower == 'clear' or cmd_lower == 'reset':
                        self.channel.send('\033[2J\033[H')
                        self._send_prompt()
                        continue

                    mitre_techniques = MITRE.analyze_command(line)
                    mitre_str = MITRE.format_techniques(mitre_techniques)

                    db.insert_command(
                        self.client_ip, self.username, line,
                        mitre_techniques=mitre_str
                    )

                    HONEYPOT_LOGGER.log_session_activity(
                        self.client_ip,
                        f"AI command: {line[:200]}",
                        username=self.username
                    )

                    response = self.engine.query(line, self.session_id)

                    if response and not self.channel.closed:
                        try:
                            self.channel.send(response)
                        except Exception:
                            self.running = False
                            return

                    if not self.channel.closed:
                        self._send_prompt()

            except (socket.timeout, OSError):
                continue
            except EOFError:
                break
            except Exception:
                break

        self._cleanup()

    def _send_prompt(self):
        if self.channel.closed:
            return
        session = self.engine.get_or_create_session(self.session_id)
        prompt = f"{session.username}@{session.hostname}:{session.cwd}{config.SHELL_PROMPT}"
        try:
            self.channel.send(prompt)
        except Exception:
            pass

    def _cleanup(self):
        self.engine.cleanup_session(self.session_id)


class AuthAcceptHandler:

    def __init__(self, client_ip: str, username: str, password: str):
        self.client_ip = client_ip
        self.username = username
        self.password = password
