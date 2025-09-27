#!/bin/bash

# SSH MCP Server Installation Script

echo "Installing SSH MCP Server..."

# Create virtual environment
echo "Creating virtual environment..."
python3 -m venv venv

# Install dependencies using virtual environment pip
echo "Installing dependencies..."
./venv/bin/pip install paramiko mcp

echo "Installation complete!"
echo ""
echo "To activate the virtual environment, run:"
echo "source venv/bin/activate"
echo ""
echo "To run the server:"
echo "./venv/bin/python ssh_mcp_server.py"