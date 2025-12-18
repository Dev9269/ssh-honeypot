import json
import threading
import time
from typing import Optional, List, Dict, Any
from datetime import datetime
from . import config
from . import logger
HONEYPOT_LOGGER = logger.get_logger()


class SessionState:
    def __init__(self, session_id: str):
        self.session_id = session_id
        self.cwd = '/root'
        self.username = 'root'
        self.hostname = 'debian-12'
        self.env: Dict[str, str] = {
            'SHELL': '/bin/bash',
            'PWD': '/root',
            'LOGNAME': 'root',
            'HOME': '/root',
            'USER': 'root',
            'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
            'TERM': 'xterm-256color',
        }
        self.history: List[str] = []
        self.created_at = datetime.now().isoformat()

    def add_command(self, cmd: str):
        self.history.append(cmd)
        if len(self.history) > config.AI_MAX_HISTORY:
            self.history = self.history[-config.AI_MAX_HISTORY:]

    def get_context(self) -> str:
        if not self.history:
            return ''
        return ' | '.join(self.history[-config.AI_MAX_HISTORY:])

    def update_from_command(self, cmd: str):
        stripped = cmd.strip()
        if stripped.startswith('cd '):
            target = stripped[3:].strip()
            if target.startswith('/'):
                self.cwd = target
            elif target == '..':
                parts = self.cwd.rstrip('/').split('/')
                if len(parts) > 1:
                    self.cwd = '/'.join(parts[:-1]) or '/'
            elif target == '~' or target == '':
                self.cwd = '/root'
            else:
                self.cwd = f"{self.cwd.rstrip('/')}/{target}"
            self.env['PWD'] = self.cwd
        elif stripped.startswith('export '):
            parts = stripped[7:].split('=', 1)
            if len(parts) == 2:
                self.env[parts[0].strip()] = parts[1].strip()

    def to_prompt_context(self) -> str:
        result = f"Current directory: {self.cwd}\n"
        result += f"Current user: {self.username}@{self.hostname}\n"
        if self.history:
            result += f"Recent command history: {self.get_context()}\n"
        return result


class OllamaEngine:

    def __init__(self):
        self._session_states: Dict[str, SessionState] = {}
        self._lock = threading.Lock()
        self._available = None
        self._model_loaded = None

    def _check_available(self) -> bool:
        if self._available is not None:
            return self._available
        try:
            import requests
            resp = requests.get(
                f"{config.AI_OLLAMA_ENDPOINT}/api/tags",
                timeout=3
            )
            if resp.status_code == 200:
                models = resp.json().get('models', [])
                model_names = [m['name'] for m in models]
                self._available = True
                self._model_loaded = config.AI_MODEL in model_names
                return True
        except Exception:
            pass
        self._available = False
        return False

    def get_or_create_session(self, session_id: str) -> SessionState:
        with self._lock:
            if session_id not in self._session_states:
                self._session_states[session_id] = SessionState(session_id)
            return self._session_states[session_id]
    def cleanup_session(self, session_id: str):
        with self._lock:
            self._session_states.pop(session_id, None)

    def query(self, cmd: str, session_id: str) -> str:
        session = self.get_or_create_session(session_id)
        session.add_command(cmd)
        session.update_from_command(cmd)

        self._available = None
        available = self._check_available()
        if not available:
            if config.AI_FALLBACK_TO_STATIC:
                return self._fallback_response(cmd, session)
            return self._timeout_response()

        try:
            return self._query_ollama(cmd, session)
        except Exception as e:
            HONEYPOT_LOGGER.log_session_activity(
                session_id.split(':')[0] if ':' in session_id else session_id,
                f"AI query failed: {e}, using fallback"
            )
            if config.AI_FALLBACK_TO_STATIC:
                return self._fallback_response(cmd, session)
            return self._error_response()

    def _query_ollama(self, cmd: str, session: SessionState) -> str:
        import requests

        context = session.to_prompt_context()
        prompt = f"{config.AI_SYSTEM_PROMPT}\n\n{context}\nAttacker command: {cmd}"

        payload = {
            'model': config.AI_MODEL,
            'prompt': prompt,
            'stream': False,
            'options': {
                'temperature': 0.1,
                'top_p': 0.9,
                'num_predict': 512,
            }
        }

        HONEYPOT_LOGGER.log_session_activity(
            session.session_id.split(':')[0] if ':' in session.session_id else session.session_id,
            f"AI request: {cmd[:100]}"
        )

        resp = requests.post(
            f"{config.AI_OLLAMA_ENDPOINT}/api/generate",
            json=payload,
            timeout=config.AI_TIMEOUT
        )

        if resp.status_code != 200:
            raise ConnectionError(f"Ollama returned {resp.status_code}")

        data = resp.json()
        response_text = data.get('response', '').strip()

        if cmd.strip() in ('exit', 'quit', 'logout'):
            response_text = 'logout\r\n'

        cleaned = self._clean_response(response_text)
        return cleaned + '\r\n' if not cleaned.endswith('\r\n') else cleaned

    def _clean_response(self, text: str) -> str:
        import re
        text = re.sub(r'```(?:bash|shell|sh|)(?:\n)?', '', text)
        text = re.sub(r'```', '', text)
        text = text.strip()
        return text

    def _fallback_response(self, cmd: str, session: SessionState = None) -> str:
        from . import shell as shell_mod
        cwd = session.cwd if session else '/root'
        return shell_mod.handle_command(cmd, '0.0.0.0', 'root', cwd=cwd)

    @staticmethod

    def _timeout_response() -> str:
        return (
            'bash: connection to upstream agent timed out\r\n'
            'bash: retrying with local fallback...\r\n'
        )

    @staticmethod

    def _error_response() -> str:
        return (
            'bash: internal error processing command\r\n'
            'bash: please try again\r\n'
        )


_engine_instance: Optional[OllamaEngine] = None


def get_engine() -> OllamaEngine:
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = OllamaEngine()
    return _engine_instance
