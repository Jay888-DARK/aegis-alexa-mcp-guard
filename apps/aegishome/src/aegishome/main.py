from pathlib import Path
from dotenv import load_dotenv, find_dotenv

# Load .env at the very top before any server or agent components are imported
load_dotenv(find_dotenv(usecwd=True))
_repo_root = Path(__file__).resolve().parents[4]
if (_repo_root / ".env").exists():
    load_dotenv(_repo_root / ".env")

import argparse
import os
import uvicorn

from aegishome.server import create_app


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the AegisHome MCP server.")
    parser.add_argument(
        "--host",
        type=str,
        default=os.getenv("AEGIS_SERVER_HOST", "127.0.0.1"),
        help="Host address to bind the server to (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.getenv("AEGIS_SERVER_PORT", "8000")),
        help="Port number to bind the server to (default: 8000)",
    )
    parser.add_argument(
        "--log-level",
        type=str,
        default=os.getenv("AEGIS_LOG_LEVEL", "info").lower(),
        help="Log level for uvicorn (default: info)",
    )
    return parser.parse_args()


def run_server() -> None:
    args = parse_args()
    print(f"Starting AegisHome MCP server on http://{args.host}:{args.port}")
    print(f"  - Streamable HTTP endpoint: http://{args.host}:{args.port}/mcp")
    print(f"  - Health check endpoint:   http://{args.host}:{args.port}/health")
    app = create_app()
    uvicorn.run(app, host=args.host, port=args.port, log_level=args.log_level)


if __name__ == "__main__":
    run_server()
