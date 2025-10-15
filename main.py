#!/usr/bin/env python3
import argparse
import sys
import os
try:
    import paramiko
except ImportError:
    print("ERROR: paramiko is not installed.")
    sys.exit(1)
try:
    import colorama
    colorama.init(autoreset=True)
except ImportError:
    pass
sys.path.insert(0, os.path.dirname(__file__))
from honeypot.server import start_server
from honeypot import config
from honeypot import db
from honeypot.dashboard import get_dashboard


def main():
    parser = argparse.ArgumentParser(
        description="SSH Honeypot v2.0 - Modern SSH attack capture & analysis platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                              # Run on default port 2222
  python main.py --port 2222                  # Run on specific port
  python main.py --config honeypot.yaml       # Use YAML config
  python main.py --dashboard                  # Enable web dashboard
  python main.py --no-shell                   # Disable fake shell
        """
    )
    parser.add_argument('--host', default=config.HOST, help=f'Host interface (default: {config.HOST})')
    parser.add_argument('--port', type=int, default=config.PORT, help=f'Port (default: {config.PORT})')
    parser.add_argument('--config', default=None, help='Path to YAML config file')
    parser.add_argument('--dashboard', action='store_true', help='Enable web dashboard')
    parser.add_argument('--ai', action='store_true', help='Enable AI-driven honeypot (Ollama)')
    parser.add_argument('--ai-model', default=None, help='Ollama model name (default: llama3.1:8b)')
    parser.add_argument('--no-shell', action='store_true', help='Disable fake shell')
    parser.add_argument('--no-geo', action='store_true', help='Disable geolocation')
    parser.add_argument('--no-db', action='store_true', help='Disable database logging')
    parser.add_argument('--blacklist', default=None, help='Comma separated IPs/CIDRs to block')
    parser.add_argument('--whitelist', default=None, help='Comma separated IPs/CIDRs to allow')
    parser.add_argument('--version', action='version', version='SSH Honeypot v2.0.0')
    args = parser.parse_args()
    if args.config:
        config.load_yaml_config(args.config)
    config.HOST = args.host
    config.PORT = args.port
    if args.dashboard:
        config.DASHBOARD_ENABLED = True
    if args.ai:
        config.AI_ENABLED = True
    if args.ai_model:
        config.AI_MODEL = args.ai_model
    if args.no_shell:
        config.SHELL_ENABLED = False
    if args.no_geo:
        config.GEO_ENABLED = False
    if args.no_db:
        config.DB_ENABLED = False
    if args.blacklist:
        config.BLACKLIST = [x.strip() for x in args.blacklist.split(',') if x.strip()]
    if args.whitelist:
        config.WHITELIST = [x.strip() for x in args.whitelist.split(',') if x.strip()]
    if config.DB_ENABLED:
        db.init_db()
    if config.DASHBOARD_ENABLED:
        dashboard = get_dashboard()
        dashboard.start()

    if config.AI_ENABLED:
        print(f"[*] AI Mode: enabled (model={config.AI_MODEL}, endpoint={config.AI_OLLAMA_ENDPOINT})")
        if config.AI_ACCEPT_ANY_AUTH:
            print(f"[*] AI Trap Mode: accepting any username/password")
    else:
        print("[*] AI Mode: disabled (use --ai to enable)")

    try:
        start_server(host=config.HOST, port=config.PORT)
    except Exception as e:
        print(f"[!] Failed to start honeypot: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
