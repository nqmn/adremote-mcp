#!/usr/bin/env sh
set -eu

# SSH MCP Server Installation Script

VENV_DIR="${VENV_DIR:-.venv-linux}"

echo "Installing SSH MCP Server for WSL/Linux..."

# Create virtual environment
echo "Creating virtual environment: $VENV_DIR"
python3 -m venv "$VENV_DIR"

# Install dependencies using virtual environment pip
echo "Installing dependencies..."
"$VENV_DIR/bin/python" -m pip install -r requirements.txt

echo "Installation complete!"
echo ""
echo "To activate the virtual environment, run:"
echo ". $VENV_DIR/bin/activate"
echo ""
echo "To run the server:"
echo "$VENV_DIR/bin/python ssh_mcp_server.py"
