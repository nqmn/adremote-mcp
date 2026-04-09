# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a single-file Python MCP (Model Context Protocol) server (`ssh_mcp_server.py`) that exposes SSH operations to Claude as tools. It enables Claude to connect to remote servers, execute commands, and transfer files via SFTP.

## Setup & Running

```bash
# Install dependencies
pip install -r requirements.txt

# Or use the install script (creates a venv)
bash install.sh

# Run the server directly (used by Claude via stdio)
python ssh_mcp_server.py

# Or with the venv created by install.sh
./venv/bin/python ssh_mcp_server.py
```

## MCP Client Configuration

For Claude Code, add to your MCP config (see `claude_config_example.json` for a Windows example using the venv):

```json
{
  "ssh-remote": {
    "command": "python",
    "args": ["/absolute/path/to/ssh_mcp_server.py"]
  }
}
```

## Architecture

All logic lives in `ssh_mcp_server.py`. Two main classes:

- **`SSHConnection`** (dataclass): Holds a `paramiko.SSHClient` instance plus metadata (hostname, username, port, connected flag, last_used timestamp).
- **`SSHMCPServer`**: Wraps `mcp.server.Server`, maintains a `Dict[str, SSHConnection]` keyed by connection name, and registers 7 tools:
  - `ssh_connect` — establish connection (password or private key auth)
  - `ssh_execute` — run a shell command, returns stdout/stderr/exit code
  - `ssh_upload_file` / `ssh_download_file` — SFTP transfers
  - `ssh_disconnect` — close and remove a connection
  - `ssh_list_connections` — enumerate active connections
  - `ssh_health_check` — ping connections with `echo 'health_check'` + `uptime`

The server runs over stdio (`mcp.server.stdio.stdio_server`), meaning it is launched as a subprocess by the MCP client and communicates via stdin/stdout — it is not an HTTP server.

## Code Style

- Formatter: `black` (line-length=88)
- Import sorting: `isort` with `black` profile
- Python 3.8+ required
