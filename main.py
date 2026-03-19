#!/usr/bin/env python3
"""
SSH Honeypot - A Python-based SSH honeypot for capturing attack attempts

Owner: Jainammaru_
GitHub: https://github.com/Dev9269
Instagram: https://www.instagram.com/jainammaru_/
LinkedIn: https://www.linkedin.com/in/jainam-maru-007803386/
"""
# Created by: jainam maru

import argparse
import sys
import os

# Check for required dependencies
try:
    import paramiko
except ImportError:
    print("ERROR: paramiko is not installed. Please install it with: pip install paramiko")
    sys.exit(1)

try:
    import colorama
except ImportError:
    print("WARNING: colorama is not installed. Colored output will be disabled.")
    print("Install it with: pip install colorama")

# Add the current directory to the path so we can import the honeypot package
sys.path.insert(0, os.path.dirname(__file__))

from honeypot.server import start_server
from honeypot import config

def main():
    """Main entry point for the SSH honeypot."""
    parser = argparse.ArgumentParser(
        description="SSH Honeypot - Capture SSH attack attempts",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                    # Run on default port 2222
  python main.py --port 2222       # Run on specific port
  python main.py --host 0.0.0.0    # Bind to specific interface
        """
    )
    
    parser.add_argument(
        '--host',
        default=config.HOST,
        help=f'Host interface to bind to (default: {config.HOST})'
    )
    
    parser.add_argument(
        '--port',
        type=int,
        default=config.PORT,
        help=f'Port to listen on (default: {config.PORT})'
    )

    parser.add_argument(
        '--blacklist',
        default=None,
        help='Comma separated list of IPs/CIDRs to block (e.g. 192.0.2.0/24,10.0.0.5)'
    )

    parser.add_argument(
        '--whitelist',
        default=None,
        help='Comma separated list of IPs/CIDRs to allow (overrides blacklist)'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='SSH Honeypot v1.0.0'
    )
    
    args = parser.parse_args()
    
    # Update config with command line arguments
    config.HOST = args.host
    config.PORT = args.port

    if args.blacklist:
        config.BLACKLIST = [x.strip() for x in args.blacklist.split(',') if x.strip()]

    if args.whitelist:
        config.WHITELIST = [x.strip() for x in args.whitelist.split(',') if x.strip()]

    # Start the server
    try:
        start_server(host=args.host, port=args.port)
    except Exception as e:
        print(f"[!] Failed to start honeypot: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()