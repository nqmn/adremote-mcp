#!/usr/bin/env sh
set -eu

REPO_URL="https://github.com/nqmn/adremote-mcp"
INSTALL_DIR="${ADREMOTE_DIR:-$HOME/adremote-mcp}"
VENV_DIR=".venv-linux"

# If already inside the repo, install in place
if [ -f "./ssh_mcp_server.py" ]; then
    INSTALL_DIR="$(pwd)"
    echo "Found ssh_mcp_server.py — installing in current directory."
else
    if ! command -v git >/dev/null 2>&1; then
        echo "Error: git is required. Install git and try again." >&2
        exit 1
    fi
    echo "Cloning adremote-mcp into $INSTALL_DIR ..."
    git clone "$REPO_URL" "$INSTALL_DIR"
    cd "$INSTALL_DIR"
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "Error: python3 is required. Install Python 3.10+ and try again." >&2
    exit 1
fi

echo "Creating virtual environment: $VENV_DIR"
python3 -m venv "$INSTALL_DIR/$VENV_DIR"

echo "Installing dependencies..."
"$INSTALL_DIR/$VENV_DIR/bin/python" -m pip install --quiet --upgrade pip
"$INSTALL_DIR/$VENV_DIR/bin/python" -m pip install --quiet -r "$INSTALL_DIR/requirements.txt"

echo ""
echo "Installation complete."
echo ""
echo "Add this to your MCP client config:"
echo "  {"
echo "    \"mcpServers\": {"
echo "      \"ssh-remote\": {"
echo "        \"command\": \"$INSTALL_DIR/$VENV_DIR/bin/python\","
echo "        \"args\": [\"$INSTALL_DIR/ssh_mcp_server.py\"]"
echo "      }"
echo "    }"
echo "  }"
