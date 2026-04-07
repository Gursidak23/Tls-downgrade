#!/usr/bin/env python3
"""
Launch the TLS Downgrade Analyzer web dashboard.

Usage:
  python dashboard.py               # default: http://127.0.0.1:5000
  python dashboard.py --port 8080   # custom port
  python dashboard.py --no-debug    # production mode (disable reloader)
"""

import os

import click
from dotenv import load_dotenv

load_dotenv()


@click.command()
@click.option("--host", default=None, help="Bind address (default from .env or 127.0.0.1)")
@click.option("--port", "-p", default=None, type=int, help="Port number (default from .env or 5000)")
@click.option("--debug/--no-debug", default=None, help="Debug mode (default: True unless FLASK_ENV=production)")
def main(host, port, debug):
    """Launch the TLS Downgrade Analyzer Dashboard"""
    from src.dashboard.app import create_app

    app = create_app()

    host = host or os.environ.get("DASHBOARD_HOST", "127.0.0.1")
    port = port or int(os.environ.get("DASHBOARD_PORT", 5000))
    if debug is None:
        debug = os.environ.get("FLASK_ENV") != "production"

    print(f"\n  TLS Downgrade & Cipher Suite Analyzer Dashboard")
    print(f"  Open http://{host}:{port} in your browser")
    if debug:
        print(f"  Debug mode: ON (do NOT use in production)")
    print()

    app.run(host=host, port=port, debug=debug)


if __name__ == "__main__":
    main()
