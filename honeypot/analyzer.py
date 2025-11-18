from typing import Dict, List, Optional
from . import config


MITRE_TECHNIQUES = {
    'password_brute_force': {
        'id': 'T1110',
        'name': 'Brute Force',
        'description': 'Adversaries may use brute force techniques to gain access to accounts.',
        'tactic': 'Credential Access',
    },
    'ssh_key_auth': {
        'id': 'T1098',
        'name': 'Account Manipulation',
        'description': 'Adversaries may manipulate accounts to maintain access.',
        'tactic': 'Persistence',
    },
    'command_execution': {
        'id': 'T1059',
        'name': 'Command and Scripting Interpreter',
        'description': 'Adversaries may abuse command interpreters to execute commands.',
        'tactic': 'Execution',
    },
    'reconnaissance': {
        'id': 'T1046',
        'name': 'Network Service Discovery',
        'description': 'Adversaries may attempt to discover services running on remote hosts.',
        'tactic': 'Discovery',
    },
    'file_transfer': {
        'id': 'T1048',
        'name': 'Exfiltration Over Alternative Protocol',
        'description': 'Adversaries may steal data by exfiltrating it over a different protocol.',
        'tactic': 'Exfiltration',
    },
    'privilege_escalation': {
        'id': 'T1068',
        'name': 'Exploitation for Privilege Escalation',
        'description': 'Adversaries may exploit vulnerabilities to gain elevated privileges.',
        'tactic': 'Privilege Escalation',
    },
    'lateral_movement': {
        'id': 'T1021',
        'name': 'Remote Services',
        'description': 'Adversaries may use remote services to move laterally.',
        'tactic': 'Lateral Movement',
    },
    'persistence_ssh': {
        'id': 'T1098.004',
        'name': 'SSH Authorized Keys',
        'description': 'Adversaries may modify SSH authorized keys to maintain persistence.',
        'tactic': 'Persistence',
    },
    'defense_evasion': {
        'id': 'T1562',
        'name': 'Impair Defenses',
        'description': 'Adversaries may maliciously modify defenses to avoid detection.',
        'tactic': 'Defense Evasion',
    },
    'collection': {
        'id': 'T1005',
        'name': 'Data from Local System',
        'description': 'Adversaries may search local system sources for data of interest.',
        'tactic': 'Collection',
    },
}


class MitreAnalyzer:
    def __init__(self):
        self.enabled = config.MITRE_ENABLED

    def analyze_auth_attempt(self, username: str, method: str) -> List[Dict]:
        if not self.enabled:
            return []
        techniques = []
        if method == 'password':
            techniques.append(MITRE_TECHNIQUES['password_brute_force'])
        elif method == 'publickey':
            techniques.append(MITRE_TECHNIQUES['ssh_key_auth'])
        return techniques
    def analyze_command(self, command: str) -> List[Dict]:
        if not self.enabled:
            return []
        techniques = []
        techniques.append(MITRE_TECHNIQUES['command_execution'])
        cmd_lower = command.lower().strip()
        if any(w in cmd_lower for w in ['wget', 'curl', 'fetch', 'scp', 'rsync']):
            techniques.append(MITRE_TECHNIQUES['file_transfer'])
        if any(w in cmd_lower for w in ['sudo', 'su ', 'chmod', 'chown', 'passwd']):
            techniques.append(MITRE_TECHNIQUES['privilege_escalation'])
        if any(w in cmd_lower for w in ['ssh ', 'telnet', 'nc ', 'ncat']):
            techniques.append(MITRE_TECHNIQUES['lateral_movement'])
        if any(w in cmd_lower for w in ['cat ', 'find ', 'grep ', 'ls -la', 'whoami', 'id', 'uname']):
            techniques.append(MITRE_TECHNIQUES['reconnaissance'])
        if any(w in cmd_lower for w in ['nmap', 'masscan', 'zmap']):
            techniques.append(MITRE_TECHNIQUES['reconnaissance'])
        if any(w in cmd_lower for w in ['rm -rf', 'dd if=', 'mkfs', 'shutdown', 'reboot']):
            techniques.append(MITRE_TECHNIQUES['defense_evasion'])
        if any(w in cmd_lower for w in ['tar ', 'zip ', 'gzip', 'base64']):
            techniques.append(MITRE_TECHNIQUES['collection'])
        return techniques

    def format_techniques(self, techniques: List[Dict]) -> str:
        if not techniques:
            return ''
        return ';'.join(f"{t['id']}:{t['name']}" for t in techniques)


_mitre_instance: Optional[MitreAnalyzer] = None


def get_mitre() -> MitreAnalyzer:
    global _mitre_instance
    if _mitre_instance is None:
        _mitre_instance = MitreAnalyzer()
    return _mitre_instance
