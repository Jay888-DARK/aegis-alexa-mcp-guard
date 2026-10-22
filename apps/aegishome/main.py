"""Forwarding entry point for aegishome.main."""

from pathlib import Path
from dotenv import load_dotenv, find_dotenv

load_dotenv(find_dotenv(usecwd=True))
_root = Path(__file__).resolve().parent.parent
if (_root / ".env").exists():
    load_dotenv(_root / ".env")

from aegishome.main import run_server

if __name__ == "__main__":
    run_server()
