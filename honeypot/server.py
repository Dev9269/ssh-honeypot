import os
import socket
import threading
import time
import ipaddress
import random
import select
import paramiko
from . import config
from . import logger
from . import db
from . import geo
from . import intel
from . import alerts
from . import ratelimiter
from . import analyzer
from . import shell as shell_mod
from . import ai_shell
from . import ai_engine as ai_engine_mod
try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    _COLORAMA_AVAILABLE = True
    _COLOR_GREEN = Fore.GREEN
    _COLOR_YELLOW = Fore.YELLOW
    _COLOR_RED = Fore.RED
    _COLOR_CYAN = Fore.CYAN
except ImportError:
    _COLORAMA_AVAILABLE = False
    _COLOR_GREEN = _COLOR_YELLOW = _COLOR_RED = _COLOR_CYAN = None
HONEYPOT_LOGGER = logger.get_logger()
GEO = geo.get_geo()
INTEL = intel.get_intel()
ALERTS = alerts.get_alerts()
LIMITER = ratelimiter.get_limiter()
MITRE = analyzer.get_mitre()


def _format_message(message: str, color: str = None) -> str:
    if _COLORAMA_AVAILABLE and color:
        return f"{color}{message}{Style.RESET_ALL}"
    return message


def _ip_in_cidrs(ip: str, cidr_list):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for cidr in cidr_list:
        try:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


def _is_ip_allowed(ip: str) -> bool:
    if config.WHITELIST:
        return _ip_in_cidrs(ip, config.WHITELIST)
    if config.BLACKLIST:
        return not _ip_in_cidrs(ip, config.BLACKLIST)
    return True


def _enrich_ip(ip: str) -> dict:
    info = {'country': '', 'city': '', 'asn': '', 'isp': '', 'threat_score': 0, 'severity': 'info'}
    geo_info = GEO.lookup(ip)
    if not geo_info.get('country') and geo_info.get('country') == '':
        geo_info = GEO.lookup_online(ip)
    info.update(geo_info)
    if config.INTEL_ENABLED:
        threat_score = INTEL.get_threat_score(ip)
        info['threat_score'] = threat_score
        info['severity'] = INTEL.get_severity(threat_score)
    return info


class HoneypotServer(paramiko.ServerInterface):
    def __init__(self, client_ip, client_port=0):
        self.client_ip = client_ip
        self.client_port = client_port
        self.event = threading.Event()
        self.username = ''
        self.auth_method = ''
        self._channel = None
    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return 0
        return 1

    def check_auth_password(self, username, password):
        time.sleep(config.AUTH_DELAY)
        self.username = username
        self.auth_method = 'password'

        mitre_techniques = MITRE.analyze_auth_attempt(username, 'password')
        mitre_str = MITRE.format_techniques(mitre_techniques)

        HONEYPOT_LOGGER.log_attempt(
            ip=self.client_ip,
            username=username,
            password=password,
            method='password',
            mitre=mitre_str,
        )

        db.insert_auth_attempt(
            self.client_ip, username, password, 'password',
            mitre_techniques=mitre_str
        )

        ALERTS.send_alert(
            'SSH Auth Attempt',
            f"Password attempt from {self.client_ip} as '{username}'",
            'low',
            {'ip': self.client_ip, 'username': username, 'method': 'password'}
        )

        if config.AI_ENABLED and config.AI_ACCEPT_ANY_AUTH:
            print(f"[+] ACCEPTED auth for {username}@{self.client_ip} (AI trap mode)")
            return paramiko.AUTH_SUCCESSFUL

        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        time.sleep(config.AUTH_DELAY)
        self.username = username
        self.auth_method = 'publickey'

        key_fingerprint = key.get_fingerprint().hex()
        mitre_techniques = MITRE.analyze_auth_attempt(username, 'publickey')
        mitre_str = MITRE.format_techniques(mitre_techniques)

        HONEYPOT_LOGGER.log_attempt(
            ip=self.client_ip,
            username=username,
            password=f"[SSH Key: {key_fingerprint}]",
            method='publickey',
            mitre=mitre_str,
        )

        db.insert_auth_attempt(
            self.client_ip, username, f"[SSH Key: {key_fingerprint}]", 'publickey',
            mitre_techniques=mitre_str
        )

        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password,publickey"

    def check_channel_shell_request(self, channel):
        self._channel = channel
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_exec_request(self, channel, command):
        cmd = command.decode('utf-8', errors='ignore') if isinstance(command, bytes) else str(command)
        HONEYPOT_LOGGER.log_attempt(
            ip=self.client_ip,
            username=self.username or "[COMMAND]",
            password=cmd,
            method='exec',
        )
        db.insert_command(self.client_ip, self.username or '', cmd)

        mitre_techniques = MITRE.analyze_command(cmd)
        mitre_str = MITRE.format_techniques(mitre_techniques)

        if config.SHELL_ENABLED:
            response = shell_mod.handle_command(cmd, self.client_ip, self.username or '')
            if channel and not channel.closed:
                try:
                    channel.send(response)
                except Exception:
                    pass
        return False


class FakeShellHandler:

    def __init__(self, channel, client_ip, username='root'):
        self.channel = channel
        self.client_ip = client_ip
        self.username = username
        self.running = True

    def start(self):
        self.channel.send(config.SHELL_BANNER)
        self.channel.send(shell_mod.get_prompt(self.username))
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
                    cmd = data.decode('utf-8', errors='ignore')
                except Exception:
                    cmd = str(data)

                cmd = cmd.replace('\r\n', '\n').replace('\r', '\n')
                for line in cmd.split('\n'):
                    if not line:
                        continue
                    response = shell_mod.handle_command(line, self.client_ip, self.username)
                    if response and not self.channel.closed:
                        try:
                            self.channel.send(response)
                        except Exception:
                            self.running = False
                            return
                    if line.strip() in ('exit', 'quit', 'logout'):
                        self.running = False
                        try:
                            self.channel.send('logout\r\n')
                            self.channel.close()
                        except Exception:
                            pass
                        return
                    if self.running and not self.channel.closed:
                        try:
                            self.channel.send(shell_mod.get_prompt(self.username))
                        except Exception:
                            self.running = False
                            return
            except (socket.timeout, OSError):
                continue
            except EOFError:
                break
            except Exception:
                break


def _check_rate_limit(ip: str) -> bool:
    if not LIMITER.is_allowed(ip):
        msg = f"[-] Rate limit exceeded for {ip}"
        print(_format_message(msg, _COLOR_RED))
        db.block_ip(ip, reason='rate_limit', duration=config.RATE_LIMIT_BAN_DURATION)
        HONEYPOT_LOGGER.log_session_activity(ip, "blocked by rate limiter")
        return False
    return True


def handle_client(client_socket, addr):
    client_ip = addr[0]
    client_port = addr[1]

    if not _is_ip_allowed(client_ip):
        msg = f"[-] Drop connection from blocked IP {client_ip}:{client_port}"
        print(_format_message(msg, _COLOR_YELLOW))
        HONEYPOT_LOGGER.log_session_activity(client_ip, "blocked by blacklist/whitelist")
        try:
            client_socket.close()
        except Exception:
            pass
        return

    if db.is_ip_blocked(client_ip):
        msg = f"[-] Drop connection from banned IP {client_ip}:{client_port}"
        print(_format_message(msg, _COLOR_YELLOW))
        try:
            client_socket.close()
        except Exception:
            pass
        return

    if not _check_rate_limit(client_ip):
        try:
            client_socket.close()
        except Exception:
            pass
        return

    conn_id = db.insert_connection(client_ip, client_port)
    start_time = time.time()

    transport = None
    try:
        ip_info = _enrich_ip(client_ip)
        geo_str = f" [{ip_info['city']}, {ip_info['country']}]" if ip_info.get('city') else ''
        threat_str = f" [threat: {ip_info['threat_score']}/10]" if ip_info.get('threat_score') else ''
        print(_format_message(f"[+] Connection from {client_ip}:{client_port}{geo_str}{threat_str}", _COLOR_GREEN))

        HONEYPOT_LOGGER.log_session_activity(
            client_ip,
            f"connected from {client_ip}:{client_port} | {geo_str} | score={ip_info['threat_score']}"
        )

        if ip_info.get('threat_score', 0) >= 5:
            ALERTS.send_alert(
                'High-Risk Connection',
                f"Connection from {client_ip} (threat score: {ip_info['threat_score']})",
                ip_info.get('severity', 'high'),
                {'ip': client_ip, 'threat_score': ip_info['threat_score'], 'country': ip_info.get('country'), 'city': ip_info.get('city')}
            )

        transport = paramiko.Transport(client_socket)
        transport.local_version = random.choice(config.FINGERPRINT_BANNERS)
        transport.set_gss_host(socket.getfqdn(""))

        try:
            host_key = paramiko.RSAKey(filename=config.HOST_KEY_PATH)
        except (paramiko.SSHException, FileNotFoundError):
            host_key = paramiko.RSAKey.generate(2048)
            host_key.write_private_key_file(config.HOST_KEY_PATH)
        transport.add_server_key(host_key)

        server = HoneypotServer(client_ip, client_port)
        try:
            transport.start_server(server=server)
        except paramiko.SSHException as e:
            print(f"[-] SSH negotiation failed: {e}")
            return

        channel = transport.accept(20)
        if channel is None:
            print(f"[-] No channel from {client_ip}")
            return

        if config.AI_ENABLED:
            if channel and not channel.closed:
                try:
                    shell = ai_shell.AIShellHandler(channel, client_ip, server.username or 'root')
                    shell.start()
                except Exception as e:
                    print(f"[-] AI Shell error: {e}")
                    if config.AI_FALLBACK_TO_STATIC and channel and not channel.closed:
                        try:
                            shell = FakeShellHandler(channel, client_ip, server.username or 'root')
                            shell.start()
                        except Exception:
                            pass
        elif config.SHELL_ENABLED and channel and not channel.closed:
            try:
                shell = FakeShellHandler(channel, client_ip)
                shell.start()
            except Exception as e:
                print(f"[-] Shell error: {e}")
        else:
            while transport.is_active():
                time.sleep(1)

    except Exception as e:
        print(_format_message(f"[-] Error handling client {client_ip}: {e}", _COLOR_RED))
    finally:
        if transport is not None:
            try:
                transport.close()
            except Exception:
                pass
        duration = time.time() - start_time
        if conn_id:
            db.update_connection_end(conn_id, duration)
        print(_format_message(f"[-] Connection closed from {client_ip} (duration: {duration:.1f}s)", _COLOR_YELLOW))
        HONEYPOT_LOGGER.log_session_activity(client_ip, f"connection closed (duration: {duration:.1f}s)")


def start_server(host=config.HOST, port=config.PORT):
    db.init_db()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    AI_ENGINE = None
    if config.AI_ENABLED:
        AI_ENGINE = ai_engine_mod.get_engine()
        print(_format_message(f"[*] AI Engine: {config.AI_MODEL} @ {config.AI_OLLAMA_ENDPOINT}", _COLOR_CYAN))
        if config.AI_ACCEPT_ANY_AUTH:
            print(_format_message(f"[*] AI Trap Mode: accepting any credentials", _COLOR_CYAN))

    try:
        sock.bind((host, port))
        sock.listen(config.BACKLOG)
        sock.settimeout(1.0)

        print(_format_message(f"[*] SSH Honeypot v2.0.0 listening on {host}:{port}", _COLOR_GREEN))
        print(_format_message(f"[*] Fake banner: {config.FINGERPRINT_BANNERS[0]}", _COLOR_GREEN))
        print(_format_message(f"[*] Logs: {config.LOG_FILE}, {config.JSON_LOG_FILE}", _COLOR_GREEN))
        if config.DB_ENABLED:
            print(_format_message(f"[*] Database: {config.DB_PATH}", _COLOR_CYAN))
        if config.GEO_ENABLED and GEO:
            print(_format_message(f"[*] Geolocation: enabled", _COLOR_CYAN))
        if config.INTEL_ENABLED:
            print(_format_message(f"[*] Threat Intelligence: enabled", _COLOR_CYAN))
        if config.ALERT_ENABLED:
            print(_format_message(f"[*] Alerts: enabled", _COLOR_CYAN))
        if config.SHELL_ENABLED:
            print(_format_message(f"[*] Fake Shell: enabled ({config.SHELL_HOSTNAME})", _COLOR_CYAN))
        if config.DASHBOARD_ENABLED:
            print(_format_message(f"[*] Dashboard: http://{config.DASHBOARD_HOST}:{config.DASHBOARD_PORT}", _COLOR_CYAN))
        if config.WHITELIST:
            print(_format_message(f"[*] Whitelist active: {config.WHITELIST}", _COLOR_GREEN))
        if config.BLACKLIST:
            print(_format_message(f"[*] Blacklist active: {config.BLACKLIST}", _COLOR_GREEN))
        print(_format_message("[*] Press Ctrl+C to stop", _COLOR_GREEN))

        while True:
            try:
                client_socket, addr = sock.accept()
                client_thread = threading.Thread(
                    target=handle_client,
                    args=(client_socket, addr)
                )
                client_thread.daemon = True
                client_thread.start()
            except socket.timeout:
                continue

    except KeyboardInterrupt:
        print("\n[*] Shutting down honeypot...")
    except Exception as e:
        print(f"[!] Server error: {e}")
    finally:
        sock.close()


if __name__ == "__main__":
    start_server()
