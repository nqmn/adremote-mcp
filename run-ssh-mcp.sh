#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

if [ -x "$SCRIPT_DIR/.venv-linux/bin/python" ]; then
  exec "$SCRIPT_DIR/.venv-linux/bin/python" "$SCRIPT_DIR/ssh_mcp_server.py"
fi

if [ -x "$SCRIPT_DIR/venv/bin/python" ]; then
  exec "$SCRIPT_DIR/venv/bin/python" "$SCRIPT_DIR/ssh_mcp_server.py"
fi

if command -v python3 >/dev/null 2>&1; then
  exec python3 "$SCRIPT_DIR/ssh_mcp_server.py"
fi

if command -v python >/dev/null 2>&1; then
  exec python "$SCRIPT_DIR/ssh_mcp_server.py"
fi

echo "No Python was found. Run ./install.sh or install Python 3.10+." >&2
exit 1
