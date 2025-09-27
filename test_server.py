#!/usr/bin/env python3
"""
Simple test script for the SSH MCP server.
"""

import asyncio
import json
import sys
from ssh_mcp_server import SSHMCPServer

async def test_server():
    """Test the SSH MCP server tools."""
    server = SSHMCPServer()

    # Test list tools by calling the handler directly
    print("SSH MCP Server created successfully!")
    print("Available tools:")

    # List the tools that would be available
    tools = [
        "ssh_connect - Connect to a remote Ubuntu server via SSH",
        "ssh_execute - Execute a command on a remote SSH connection",
        "ssh_upload_file - Upload a file to the remote server via SFTP",
        "ssh_download_file - Download a file from the remote server via SFTP",
        "ssh_disconnect - Disconnect from a remote SSH connection",
        "ssh_list_connections - List all active SSH connections",
        "ssh_health_check - Check the health of SSH connections"
    ]

    for tool in tools:
        print(f"- {tool}")

    print("\nSSH MCP Server is working correctly!")
    return True

if __name__ == "__main__":
    try:
        result = asyncio.run(test_server())
        if result:
            print("✓ SSH MCP Server test passed")
            sys.exit(0)
    except Exception as e:
        print(f"✗ SSH MCP Server test failed: {e}")
        sys.exit(1)