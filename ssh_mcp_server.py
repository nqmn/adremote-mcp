#!/usr/bin/env python3
"""
SSH MCP Server - Model Context Protocol server for remote SSH connections to Ubuntu servers.
Provides tools for connecting to remote Ubuntu servers via SSH and executing commands.
"""

import asyncio
import json
import logging
import sys
import time
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass
from pathlib import Path

import paramiko
from paramiko import AutoAddPolicy
from mcp.server import Server
from mcp.server.models import InitializationOptions
from mcp.server.stdio import stdio_server
from mcp.types import (
    Tool,
    TextContent,
    ImageContent,
    EmbeddedResource,
    CallToolRequest,
    CallToolResult,
    ListToolsRequest,
    ListToolsResult,
    ServerCapabilities,
    ToolsCapability,
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class SSHConnection:
    """Represents an active SSH connection."""
    client: paramiko.SSHClient
    hostname: str
    username: str
    port: int
    connected: bool = False
    last_used: float = 0.0

    def __post_init__(self):
        self.last_used = time.time()

class SSHMCPServer:
    """MCP Server for SSH operations on remote Ubuntu servers."""

    def __init__(self):
        self.server = Server("ssh-mcp-server")
        self.connections: Dict[str, SSHConnection] = {}
        self.setup_tools()

    def setup_tools(self):
        """Register all available tools."""

        @self.server.list_tools()
        async def list_tools() -> List[Tool]:
            return [
                Tool(
                    name="ssh_connect",
                    description="Connect to a remote Ubuntu server via SSH",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "hostname": {
                                "type": "string",
                                "description": "Remote server hostname or IP address"
                            },
                            "username": {
                                "type": "string",
                                "description": "SSH username"
                            },
                            "password": {
                                "type": "string",
                                "description": "SSH password (optional if using key auth)"
                            },
                            "private_key_path": {
                                "type": "string",
                                "description": "Path to private key file (optional)"
                            },
                            "port": {
                                "type": "integer",
                                "description": "SSH port (default: 22)",
                                "default": 22
                            },
                            "connection_name": {
                                "type": "string",
                                "description": "Name for this connection (default: hostname)",
                                "default": None
                            }
                        },
                        "required": ["hostname", "username"]
                    }
                ),
                Tool(
                    name="ssh_execute",
                    description="Execute a command on a remote SSH connection",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "connection_name": {
                                "type": "string",
                                "description": "Name of the SSH connection to use"
                            },
                            "command": {
                                "type": "string",
                                "description": "Command to execute on the remote server"
                            },
                            "timeout": {
                                "type": "integer",
                                "description": "Command timeout in seconds (default: 30)",
                                "default": 30
                            }
                        },
                        "required": ["connection_name", "command"]
                    }
                ),
                Tool(
                    name="ssh_upload_file",
                    description="Upload a file to the remote server via SFTP",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "connection_name": {
                                "type": "string",
                                "description": "Name of the SSH connection to use"
                            },
                            "local_path": {
                                "type": "string",
                                "description": "Local file path to upload"
                            },
                            "remote_path": {
                                "type": "string",
                                "description": "Remote destination path"
                            }
                        },
                        "required": ["connection_name", "local_path", "remote_path"]
                    }
                ),
                Tool(
                    name="ssh_download_file",
                    description="Download a file from the remote server via SFTP",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "connection_name": {
                                "type": "string",
                                "description": "Name of the SSH connection to use"
                            },
                            "remote_path": {
                                "type": "string",
                                "description": "Remote file path to download"
                            },
                            "local_path": {
                                "type": "string",
                                "description": "Local destination path"
                            }
                        },
                        "required": ["connection_name", "remote_path", "local_path"]
                    }
                ),
                Tool(
                    name="ssh_disconnect",
                    description="Disconnect from a remote SSH connection",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "connection_name": {
                                "type": "string",
                                "description": "Name of the SSH connection to disconnect"
                            }
                        },
                        "required": ["connection_name"]
                    }
                ),
                Tool(
                    name="ssh_list_connections",
                    description="List all active SSH connections",
                    inputSchema={
                        "type": "object",
                        "properties": {}
                    }
                ),
                Tool(
                    name="ssh_health_check",
                    description="Check the health of SSH connections",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "connection_name": {
                                "type": "string",
                                "description": "Name of the SSH connection to check (optional, checks all if not provided)"
                            }
                        }
                    }
                )
            ]

        @self.server.call_tool()
        async def call_tool(name: str, arguments: Dict[str, Any]) -> List[Union[TextContent, ImageContent, EmbeddedResource]]:
            try:
                if name == "ssh_connect":
                    return await self._ssh_connect(arguments)
                elif name == "ssh_execute":
                    return await self._ssh_execute(arguments)
                elif name == "ssh_upload_file":
                    return await self._ssh_upload_file(arguments)
                elif name == "ssh_download_file":
                    return await self._ssh_download_file(arguments)
                elif name == "ssh_disconnect":
                    return await self._ssh_disconnect(arguments)
                elif name == "ssh_list_connections":
                    return await self._ssh_list_connections(arguments)
                elif name == "ssh_health_check":
                    return await self._ssh_health_check(arguments)
                else:
                    return [TextContent(type="text", text=f"Unknown tool: {name}")]
            except Exception as e:
                logger.error(f"Error in tool {name}: {str(e)}")
                return [TextContent(type="text", text=f"Error: {str(e)}")]

    async def _ssh_connect(self, args: Dict[str, Any]) -> List[TextContent]:
        """Establish SSH connection to remote server."""
        hostname = args["hostname"]
        username = args["username"]
        password = args.get("password")
        private_key_path = args.get("private_key_path")
        port = args.get("port", 22)
        connection_name = args.get("connection_name", hostname)

        if connection_name in self.connections:
            return [TextContent(type="text", text=f"Connection '{connection_name}' already exists")]

        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(AutoAddPolicy())

            # Set connection timeout
            client.timeout = 10.0

            # Determine authentication method
            if private_key_path:
                private_key_path = Path(private_key_path).expanduser()
                if not private_key_path.exists():
                    return [TextContent(type="text", text=f"Private key file not found: {private_key_path}")]

                # Try different key types
                key = None
                for key_class in [paramiko.RSAKey, paramiko.ECDSAKey, paramiko.Ed25519Key]:
                    try:
                        key = key_class.from_private_key_file(str(private_key_path))
                        break
                    except paramiko.PasswordRequiredException:
                        return [TextContent(type="text", text="Private key requires a passphrase (not supported)")]
                    except Exception:
                        continue

                if key is None:
                    return [TextContent(type="text", text="Unable to load private key (unsupported format)")]

                client.connect(hostname, port=port, username=username, pkey=key, timeout=10)
            elif password:
                client.connect(hostname, port=port, username=username, password=password, timeout=10)
            else:
                return [TextContent(type="text", text="Either password or private_key_path must be provided")]

            # Test the connection
            try:
                stdin, stdout, stderr = client.exec_command("echo 'Connection test'", timeout=5)
                test_output = stdout.read().decode('utf-8').strip()
                if test_output != "Connection test":
                    logger.warning(f"Connection test failed for {hostname}")
            except Exception as e:
                logger.warning(f"Connection test warning for {hostname}: {str(e)}")

            connection = SSHConnection(
                client=client,
                hostname=hostname,
                username=username,
                port=port,
                connected=True
            )

            self.connections[connection_name] = connection

            return [TextContent(
                type="text",
                text=f"Successfully connected to {hostname}:{port} as {username} (connection: {connection_name})"
            )]

        except paramiko.AuthenticationException:
            return [TextContent(type="text", text="Authentication failed - check username/password or key")]
        except paramiko.SSHException as e:
            return [TextContent(type="text", text=f"SSH connection failed: {str(e)}")]
        except Exception as e:
            return [TextContent(type="text", text=f"Failed to connect: {str(e)}")]

    async def _ssh_execute(self, args: Dict[str, Any]) -> List[TextContent]:
        """Execute command on remote server."""
        connection_name = args["connection_name"]
        command = args["command"]
        timeout = args.get("timeout", 30)

        if connection_name not in self.connections:
            return [TextContent(type="text", text=f"Connection '{connection_name}' not found")]

        connection = self.connections[connection_name]
        if not connection.connected:
            return [TextContent(type="text", text=f"Connection '{connection_name}' is not active")]

        try:
            # Update last used timestamp
            connection.last_used = time.time()

            stdin, stdout, stderr = connection.client.exec_command(command, timeout=timeout)

            stdout_text = stdout.read().decode('utf-8')
            stderr_text = stderr.read().decode('utf-8')
            exit_code = stdout.channel.recv_exit_status()

            result = f"Command: {command}\n"
            result += f"Exit Code: {exit_code}\n\n"

            if stdout_text:
                result += f"STDOUT:\n{stdout_text}\n"

            if stderr_text:
                result += f"STDERR:\n{stderr_text}\n"

            return [TextContent(type="text", text=result)]

        except paramiko.SSHException as e:
            connection.connected = False
            return [TextContent(type="text", text=f"SSH error executing command: {str(e)}")]
        except Exception as e:
            return [TextContent(type="text", text=f"Failed to execute command: {str(e)}")]

    async def _ssh_upload_file(self, args: Dict[str, Any]) -> List[TextContent]:
        """Upload file to remote server via SFTP."""
        connection_name = args["connection_name"]
        local_path = args["local_path"]
        remote_path = args["remote_path"]

        if connection_name not in self.connections:
            return [TextContent(type="text", text=f"Connection '{connection_name}' not found")]

        connection = self.connections[connection_name]
        if not connection.connected:
            return [TextContent(type="text", text=f"Connection '{connection_name}' is not active")]

        try:
            # Check if local file exists
            if not Path(local_path).exists():
                return [TextContent(type="text", text=f"Local file not found: {local_path}")]

            # Update last used timestamp
            connection.last_used = time.time()

            sftp = connection.client.open_sftp()
            try:
                sftp.put(local_path, remote_path)
            finally:
                sftp.close()

            return [TextContent(
                type="text",
                text=f"Successfully uploaded {local_path} to {remote_path} on {connection.hostname}"
            )]

        except FileNotFoundError:
            return [TextContent(type="text", text=f"Local file not found: {local_path}")]
        except paramiko.SFTPError as e:
            return [TextContent(type="text", text=f"SFTP error: {str(e)}")]
        except Exception as e:
            return [TextContent(type="text", text=f"Failed to upload file: {str(e)}")]

    async def _ssh_download_file(self, args: Dict[str, Any]) -> List[TextContent]:
        """Download file from remote server via SFTP."""
        connection_name = args["connection_name"]
        remote_path = args["remote_path"]
        local_path = args["local_path"]

        if connection_name not in self.connections:
            return [TextContent(type="text", text=f"Connection '{connection_name}' not found")]

        connection = self.connections[connection_name]
        if not connection.connected:
            return [TextContent(type="text", text=f"Connection '{connection_name}' is not active")]

        try:
            # Update last used timestamp
            connection.last_used = time.time()

            # Create local directory if it doesn't exist
            local_dir = Path(local_path).parent
            local_dir.mkdir(parents=True, exist_ok=True)

            sftp = connection.client.open_sftp()
            try:
                sftp.get(remote_path, local_path)
            finally:
                sftp.close()

            return [TextContent(
                type="text",
                text=f"Successfully downloaded {remote_path} to {local_path} from {connection.hostname}"
            )]

        except paramiko.SFTPError as e:
            return [TextContent(type="text", text=f"SFTP error (file may not exist): {str(e)}")]
        except Exception as e:
            return [TextContent(type="text", text=f"Failed to download file: {str(e)}")]

    async def _ssh_disconnect(self, args: Dict[str, Any]) -> List[TextContent]:
        """Disconnect from SSH connection."""
        connection_name = args["connection_name"]

        if connection_name not in self.connections:
            return [TextContent(type="text", text=f"Connection '{connection_name}' not found")]

        try:
            connection = self.connections[connection_name]
            connection.client.close()
            connection.connected = False
            del self.connections[connection_name]

            return [TextContent(
                type="text",
                text=f"Disconnected from {connection.hostname} (connection: {connection_name})"
            )]

        except Exception as e:
            return [TextContent(type="text", text=f"Failed to disconnect: {str(e)}")]

    async def _ssh_list_connections(self, args: Dict[str, Any]) -> List[TextContent]:
        """List all active SSH connections."""
        if not self.connections:
            return [TextContent(type="text", text="No active SSH connections")]

        result = "Active SSH Connections:\n"
        for name, conn in self.connections.items():
            status = "Connected" if conn.connected else "Disconnected"
            last_used = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(conn.last_used))
            result += f"- {name}: {conn.username}@{conn.hostname}:{conn.port} ({status}) - Last used: {last_used}\n"

        return [TextContent(type="text", text=result)]

    async def _ssh_health_check(self, args: Dict[str, Any]) -> List[TextContent]:
        """Check the health of SSH connections."""
        connection_name = args.get("connection_name")

        if connection_name:
            # Check specific connection
            if connection_name not in self.connections:
                return [TextContent(type="text", text=f"Connection '{connection_name}' not found")]

            connection = self.connections[connection_name]
            health_status = await self._check_connection_health(connection_name, connection)
            return [TextContent(type="text", text=f"Health check for '{connection_name}':\n{health_status}")]
        else:
            # Check all connections
            if not self.connections:
                return [TextContent(type="text", text="No active SSH connections to check")]

            results = ["Health check for all connections:\n"]
            for name, conn in self.connections.items():
                health_status = await self._check_connection_health(name, conn)
                results.append(f"- {name}: {health_status}")

            return [TextContent(type="text", text="\n".join(results))]

    async def _check_connection_health(self, name: str, connection: SSHConnection) -> str:
        """Check the health of a single connection."""
        if not connection.connected:
            return "Status: Disconnected"

        try:
            # Simple test command
            stdin, stdout, stderr = connection.client.exec_command("echo 'health_check'", timeout=5)
            output = stdout.read().decode('utf-8').strip()
            exit_code = stdout.channel.recv_exit_status()

            if exit_code == 0 and output == "health_check":
                uptime_cmd = "uptime"
                stdin, stdout, stderr = connection.client.exec_command(uptime_cmd, timeout=5)
                uptime_output = stdout.read().decode('utf-8').strip()

                last_used = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(connection.last_used))
                return f"Status: Healthy, Last used: {last_used}, Server uptime: {uptime_output}"
            else:
                connection.connected = False
                return "Status: Unhealthy (test command failed)"

        except Exception as e:
            connection.connected = False
            return f"Status: Unhealthy ({str(e)})"

    async def run(self):
        """Run the MCP server."""
        async with stdio_server() as (read_stream, write_stream):
            await self.server.run(
                read_stream,
                write_stream,
                InitializationOptions(
                    server_name="ssh-mcp-server",
                    server_version="1.0.0",
                    capabilities=ServerCapabilities(
                        tools=ToolsCapability()
                    )
                )
            )

async def main():
    """Main entry point."""
    server = SSHMCPServer()
    await server.run()

if __name__ == "__main__":
    asyncio.run(main())