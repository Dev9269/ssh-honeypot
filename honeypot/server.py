import os
import socket
import threading
import time
import ipaddress

import paramiko

from . import config
from . import logger

"""
Owner: Jainammaru_
GitHub: https://github.com/Dev9269
Instagram: https://www.instagram.com/jainammaru_/
LinkedIn: https://www.linkedin.com/in/jainam-maru-007803386/
"""

# Optional colored console output
try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    _COLORAMA_AVAILABLE = True
    _COLOR_GREEN = Fore.GREEN
    _COLOR_YELLOW = Fore.YELLOW
    _COLOR_RED = Fore.RED
except ImportError:
    _COLORAMA_AVAILABLE = False
    _COLOR_GREEN = _COLOR_YELLOW = _COLOR_RED = None

# Created by: jainam maru


def _format_message(message: str, color: str = None) -> str:
    if _COLORAMA_AVAILABLE and color:
        return f"{color}{message}{Style.RESET_ALL}"
    return message

# Singleton logger instance used across threads
HONEYPOT_LOGGER = logger.get_logger()


def _ip_in_cidrs(ip: str, cidr_list):
    """Return True if the given IP is within any of the given CIDR/networks."""
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
    """Determine whether a client IP is allowed based on whitelist/blacklist."""
    if config.WHITELIST:
        return _ip_in_cidrs(ip, config.WHITELIST)

    if config.BLACKLIST:
        return not _ip_in_cidrs(ip, config.BLACKLIST)

    return True

class HoneypotServer(paramiko.ServerInterface):
    """Custom SSH server that logs authentication attempts and always rejects them."""
    
    def __init__(self, client_ip):
        self.client_ip = client_ip
        self.event = threading.Event()
        
    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return 0  # OPEN_SUCCEEDED
        return 1  # OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        
    def check_auth_password(self, username, password):
        """Log password authentication attempt and always reject."""
        # Add slight delay to simulate real server response
        time.sleep(config.AUTH_DELAY)
        
        # Log the attempt
        HONEYPOT_LOGGER.log_attempt(
            ip=self.client_ip,
            username=username,
            password=password,
            method='password',
        )
        
        # Always reject authentication
        return paramiko.AUTH_FAILED
        
    def check_auth_publickey(self, username, key):
        """Log publickey authentication attempt and always reject."""
        # Add slight delay
        time.sleep(config.AUTH_DELAY)
        
        # Log the attempt (we'll log the key fingerprint as password for simplicity)
        key_fingerprint = key.get_fingerprint().hex()
        HONEYPOT_LOGGER.log_attempt(
            ip=self.client_ip,
            username=username,
            password=f"[SSH Key: {key_fingerprint}]",
            method='publickey',
        )
        
        # Always reject authentication
        return paramiko.AUTH_FAILED
        
    def get_allowed_auths(self, username):
        """Return what authentication methods we support."""
        return "password,publickey"
        
    def check_channel_shell_request(self, channel):
        """If a shell is requested, we indicate we're ready but won't provide real shell."""
        return True
        
    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        """Accept PTY request but don't allocate real PTY."""
        return True
        
    def check_channel_exec_request(self, channel, command):
        """Log any command execution attempts."""
        HONEYPOT_LOGGER.log_attempt(
            ip=self.client_ip,
            username="[COMMAND ATTEMPT]",
            password=command.decode('utf-8', errors='ignore') if isinstance(command, bytes) else str(command),
            method='exec',
        )
        return False

def handle_client(client_socket, addr):
    """Handle an incoming SSH connection."""
    client_ip = addr[0]
    client_port = addr[1]

    # Apply optional IP filtering
    if not _is_ip_allowed(client_ip):
        msg = f"[-] Drop connection from blocked IP {client_ip}:{client_port}"
        print(_format_message(msg, _COLOR_YELLOW))
        HONEYPOT_LOGGER.log_session_activity(client_ip, "blocked by blacklist")
        try:
            client_socket.close()
        except Exception:
            pass
        return

    print(_format_message(f"[+] Connection from {client_ip}:{client_port}", _COLOR_GREEN))
    HONEYPOT_LOGGER.log_session_activity(client_ip, f"connected from {client_ip}:{client_port}")
    transport = None
    
    try:
        # Create SSH transport
        transport = paramiko.Transport(client_socket)
        transport.local_version = config.SSH_BANNER
        transport.set_gss_host(socket.getfqdn(""))
        # Load host key
        try:
            host_key = paramiko.RSAKey(filename=config.HOST_KEY_PATH)
        except (paramiko.SSHException, FileNotFoundError):
            # Generate a new host key if file doesn't exist
            host_key = paramiko.RSAKey.generate(2048)
            host_key.write_private_key_file(config.HOST_KEY_PATH)
        transport.add_server_key(host_key)
        
        # Start SSH server
        server = HoneypotServer(client_ip)
        try:
            transport.start_server(server=server)
        except paramiko.SSHException as e:
            print(f"[-] SSH negotiation failed: {e}")
            return
            
        # Wait for channel (client may request shell, exec, etc.)
        channel = transport.accept(20)
        if channel is None:
            print(f"[-] No channel from {client_ip}")
            return
            
        # Keep connection alive until client closes it
        while transport.is_active():
            time.sleep(1)
            
    except Exception as e:
        print(_format_message(f"[-] Error handling client {client_ip}: {e}", _COLOR_RED))
    finally:
        if transport is not None:
            try:
                transport.close()
            except:
                pass
        print(_format_message(f"[-] Connection closed from {client_ip}", _COLOR_YELLOW))
        HONEYPOT_LOGGER.log_session_activity(client_ip, "connection closed")

def start_server(host=config.HOST, port=config.PORT):
    """Start the SSH honeypot server."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        sock.bind((host, port))
        sock.listen(config.BACKLOG)
        print(_format_message(f"[*] SSH Honeypot listening on {host}:{port}", _COLOR_GREEN))
        print(_format_message(f"[*] Fake banner: {config.SSH_BANNER}", _COLOR_GREEN))
        print(_format_message(f"[*] Logs will be saved to {config.LOG_FILE} and {config.JSON_LOG_FILE}", _COLOR_GREEN))
        if config.WHITELIST:
            print(_format_message(f"[*] Whitelist active: {config.WHITELIST}", _COLOR_GREEN))
        if config.BLACKLIST:
            print(_format_message(f"[*] Blacklist active: {config.BLACKLIST}", _COLOR_GREEN))
        print(_format_message("[*] Press Ctrl+C to stop", _COLOR_GREEN))
        
        while True:
            client_socket, addr = sock.accept()
            client_thread = threading.Thread(
                target=handle_client,
                args=(client_socket, addr)
            )
            client_thread.daemon = True
            client_thread.start()
            
    except KeyboardInterrupt:
        print("\n[*] Shutting down honeypot...")
    except Exception as e:
        print(f"[!] Server error: {e}")
    finally:
        sock.close()

if __name__ == "__main__":
    start_server()