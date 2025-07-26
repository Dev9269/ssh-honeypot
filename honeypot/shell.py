import os
import time
import random
import re
import socket
from typing import Optional, List, Tuple
from . import config
from . import logger
from . import db
from . import analyzer
HONEYPOT_LOGGER = logger.get_logger()
MITRE = analyzer.get_mitre()


FAKE_FILESYSTEM = {
    '/': {
        'type': 'dir',
        'children': {
            'bin': {'type': 'dir', 'children': {}},
            'boot': {'type': 'dir', 'children': {}},
            'dev': {'type': 'dir', 'children': {}},
            'etc': {'type': 'dir', 'children': {
                'hostname': {'type': 'file', 'content': config.SHELL_HOSTNAME + '\n'},
                'passwd': {'type': 'file', 'content': 'root:x:0:0:root:/root:/bin/bash\nsshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin\n'},
                'shadow': {'type': 'file', 'content': 'root:!:19609:0:99999:7:::\n'},
                'ssh': {'type': 'dir', 'children': {
                    'sshd_config': {'type': 'file', 'content': 'Port 22\nPermitRootLogin yes\nPasswordAuthentication yes\n'},
                }},
                'os-release': {'type': 'file', 'content': 'PRETTY_NAME="Ubuntu 22.04.3 LTS"\n'},
            }},
            'home': {'type': 'dir', 'children': {
                'ubuntu': {'type': 'dir', 'children': {
                    '.bashrc': {'type': 'file', 'content': '# ~/.bashrc\n'},
                    '.ssh': {'type': 'dir', 'children': {
                        'authorized_keys': {'type': 'file', 'content': ''},
                        'id_rsa': {'type': 'file', 'content': '-----BEGIN OPENSSH PRIVATE KEY-----\nsample\n-----END OPENSSH PRIVATE KEY-----\n'},
                    }},
                    'notes.txt': {'type': 'file', 'content': 'TODO: update server config\n'},
                }},
            }},
            'opt': {'type': 'dir', 'children': {}},
            'proc': {'type': 'dir', 'children': {}},
            'root': {'type': 'dir', 'children': {
                '.bash_history': {'type': 'file', 'content': 'ls -la\nwhoami\n'},
            }},
            'run': {'type': 'dir', 'children': {}},
            'sbin': {'type': 'dir', 'children': {}},
            'tmp': {'type': 'dir', 'children': {}},
            'usr': {'type': 'dir', 'children': {
                'bin': {'type': 'dir', 'children': {}},
            }},
            'var': {'type': 'dir', 'children': {
                'log': {'type': 'dir', 'children': {
                    'auth.log': {'type': 'file', 'content': 'Jun 24 10:15:22 sshd[1234]: Accepted password for root\n'},
                    'syslog': {'type': 'file', 'content': 'Jun 24 10:15:00 kernel: [    0.000000] Linux version 5.15.0-91-generic\n'},
                }},
                'www': {'type': 'dir', 'children': {}},
            }},
        },
    },
}
CURRENT_DIR = '/root'


COMMAND_RESPONSES = {
    'whoami': 'root\r\n',
    'id': 'uid=0(root) gid=0(root) groups=0(root)\r\n',
    'hostname': config.SHELL_HOSTNAME + '\r\n',
    'uname -a': config.SHELL_BANNER,
    'uname -r': '5.15.0-91-generic\r\n',
    'uptime': ' 10:30:22 up 14 days,  3:45,  1 user,  load average: 0.08, 0.03, 0.01\r\n',
    'date': 'Wed Jun 24 10:30:22 UTC 2026\r\n',
    'who': 'root     pts/0        2026-06-24 10:25 (10.0.0.1)\r\n',
    'w': ' 10:30:22 up 14 days,  3:45,  1 user,  load average: 0.08, 0.03, 0.01\r\nUSER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\r\nroot     pts/0    10.0.0.1         10:25    5:00   0.02s  0.02s -bash\r\n',
    'last': 'root     pts/0        10.0.0.1         Wed Jun 24 10:25   still logged in\r\nroot     pts/0        10.0.0.1         Tue Jun 23 09:15 - 17:30  (08:15)\r\nreboot   system boot  5.15.0-91-generic Tue Jun 23 09:00   still running\r\n',
    'env': 'SHELL=/bin/bash\r\nPWD=/root\r\nLOGNAME=root\r\nHOME=/root\r\nUSER=root\r\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\r\n',
    'df -h': 'Filesystem      Size  Used Avail Use% Mounted on\r\nudev            1.9G     0  1.9G   0% /dev\r\ntmpfs           394M  1.3M  393M   1% /run\r\n/dev/sda1        49G   12G   35G  26% /\r\n',
    'free -m': '               total        used        free      shared  buff/cache   available\r\nMem:            3936        1834         456          89        1645        1812\r\nSwap:           2048           0        2048\r\n',
    'ps aux': 'USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\r\nroot         1  0.0  0.4 169564 10296 ?        Ss   Jun10   0:23 /sbin/init\r\nroot       567  0.0  0.2  72340  5648 ?        Ss   Jun10   0:01 /usr/sbin/sshd\r\nroot      1234  0.0  0.1  18640  3216 ?        Ss   10:25   0:00 sshd: root@pts/0\r\n',
    'ifconfig': 'eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\r\n        inet 10.0.0.15  netmask 255.255.255.0  broadcast 10.0.0.255\r\n        ether 00:1a:2b:3c:4d:5e  txqueuelen 1000  (Ethernet)\r\nlo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\r\n        inet 127.0.0.1  netmask 255.0.0.0\r\n',
    'ss -tlnp': 'State          Recv-Q         Send-Q                   Local Address:Port                   Peer Address:Port        Process\r\nLISTEN         0              128                          0.0.0.0:22                          0.0.0.0:*            users:(("sshd",pid=567,fd=3))\r\nLISTEN         0              128                             [::]:22                             [::]:*            users:(("sshd",pid=567,fd=4))\r\n',
    'lsblk': 'NAME   MAJ:MIN RM   SIZE RO TYPE MOUNTPOINTS\r\nsda      8:0    0    50G  0 disk\r\n├─sda1   8:1    0    49G  0 part /\r\n├─sda2   8:2    0     1G  0 part [SWAP]\r\n',
    'cat /etc/hostname': config.SHELL_HOSTNAME + '\r\n',
    'cat /etc/os-release': 'PRETTY_NAME="Ubuntu 22.04.3 LTS"\r\nNAME="Ubuntu"\r\nVERSION_ID="22.04"\r\nVERSION="22.04.3 LTS (Jammy Jellyfish)"\r\n',
}


def _normalize_cmd(cmd: str) -> str:
    cmd = cmd.strip()
    cmd = re.sub(r'\s+', ' ', cmd)
    return cmd


def _get_fake_listing(path: str) -> str:
    parts = [p for p in path.split('/') if p]
    current = FAKE_FILESYSTEM.get('/', {})
    for part in parts:
        children = current.get('children', {})
        if part in children:
            current = children[part]
        else:
            return f'ls: cannot access {path}: No such file or directory\r\n'
    if current.get('type') != 'dir':
        return f'{path}\r\n'

    children = current.get('children', {})
    if not children:
        return ''

    result = []
    for name, info in children.items():
        if info['type'] == 'dir':
            result.append(f'drwxr-xr-x 2 root root 4096 Jan 24 10:30 {name}')
        else:
            size = len(info.get('content', ''))
            result.append(f'-rw-r--r-- 1 root root {size} Jan 24 10:30 {name}')
    return '\r\n'.join(result) + '\r\n'


def _get_fake_cat(path: str) -> str:
    parts = [p for p in path.split('/') if p]
    current = FAKE_FILESYSTEM.get('/', {})
    for part in parts:
        children = current.get('children', {})
        if part in children:
            current = children[part]
        else:
            return f'cat: {path}: No such file or directory\r\n'

    if current.get('type') == 'file':
        return current.get('content', '')
    return f'cat: {path}: Is a directory\r\n'


def handle_command(cmd: str, ip: str, username: str, cwd: str = '/root') -> str:
    cmd_norm = _normalize_cmd(cmd)

    techniques = MITRE.analyze_command(cmd_norm)
    mitre_str = MITRE.format_techniques(techniques)

    db.insert_command(ip, username, cmd_norm, mitre_techniques=mitre_str)
    HONEYPOT_LOGGER.log_session_activity(
        ip, f"command: {cmd_norm}", username=username
    )

    if cmd_norm == 'pwd':
        return cwd + '\r\n'

    if cmd_norm in COMMAND_RESPONSES:
        return COMMAND_RESPONSES[cmd_norm]

    if cmd_norm.startswith('ls '):
        arg = cmd_norm[3:].strip() or '.'
        return _get_fake_listing(arg)

    if cmd_norm == 'ls':
        return _get_fake_listing('.')

    if cmd_norm.startswith('cat '):
        arg = cmd_norm[4:].strip()
        return _get_fake_cat(arg)

    if cmd_norm.startswith('cd '):
        return ''

    if cmd_norm in ('exit', 'quit', 'logout'):
        return 'logout\r\n'

    if cmd_norm in ('', '\n'):
        return ''

    if cmd_norm.startswith('echo '):
        return cmd_norm[5:] + '\r\n'

    if cmd_norm.startswith('ping '):
        host = cmd_norm[5:].strip()
        return f'PING {host} (8.8.8.8) 56(84) bytes of data.\r\n64 bytes from 8.8.8.8: icmp_seq=1 ttl=117 time=12.3 ms\r\n64 bytes from 8.8.8.8: icmp_seq=2 ttl=117 time=12.1 ms\r\n'

    if cmd_norm.startswith('curl ') or cmd_norm.startswith('wget '):
        return '--2026-06-24 10:30:22--  Resolving host... connected.\r\nHTTP request sent, awaiting response... 200 OK\r\nLength: 1234 (1.2K)\r\nSaving to: \'index.html\'\r\n100%[=======================>] 1,234  --.-K/s   in 0s\r\n\r\nindex.html saved [1234/1234]\r\n'

    if cmd_norm in ('clear', 'reset'):
        return '\033[2J\033[H'

    if cmd_norm.startswith('rm '):
        return ''

    if cmd_norm.startswith('mkdir '):
        return ''

    if cmd_norm.startswith('touch '):
        return ''

    return f'bash: {cmd_norm.split()[0]}: command not found\r\n'


def get_prompt(username: str = 'root') -> str:
    return f'{username}@{config.SHELL_HOSTNAME}:{CURRENT_DIR}{config.SHELL_PROMPT}'
