# SSH Remote MCP Server

SSH remote access for MCP-compatible clients through Model Context Protocol (MCP).

## Quick Start

1. **Install**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Add the MCP in Claude Desktop or Claude Code**:

   Use your MCP config and point it to `ssh_mcp_server.py`.

3. **Add the MCP in Codex**:

   Add the same server to your Codex MCP config.

4. **Automatic setup**:

   Download this repo, run Claude or Codex, and ask it to add this folder as a global MCP server.
   After that, you can use it directly from chat.

## Features

- Connect to remote servers via SSH
- Execute commands remotely
- Upload/download files via SFTP
- Manage multiple connections
- Health monitoring

## Usage Examples

### Connect with password:
```
Connect to 192.168.1.100 with username ubuntu and password mypass
```
The MCP first tests the SSH connection with your username and password.
If the login works, it generates or installs an SSH key, saves the key-based credential locally, and does not save the password.
The password is only used the first time.

### Connect with password for a one-off session:
```
Connect to 192.168.1.100 with username ubuntu and password mypass, save_credentials false
```
This keeps the live connection only. No reusable credential is saved and no automatic key bootstrap is attempted.

### Connect later using the saved name:
```
ssh saved-name
```
After the first successful setup, just use the saved credential name to connect again.

### Execute commands:
```
List files in /home directory on my server
Run 'top' command on the remote server
```

### File transfers:
```
Upload local file.txt to /home/user/ on the server
Download /var/log/app.log from the server
```

### Connection health and inventory:
```
Check health of all SSH connections
Show me all active SSH connections
```

## Requirements

- Python 3.10+
- paramiko
- mcp

## Latest Update

Version `1.0.1` adds safer and more practical day-to-day SSH workflows:

- Direct logins still save reusable credentials by default, but `save_credentials=false` now cleanly opts out for password sessions too
- Saved credential flows now include connect, save, list, delete, and manual key setup helpers
- Host trust and file transfer rules are stricter, with local root restrictions and trust-on-first-use host pinning
- Saved credentials are key-based, so no master password is required for normal use
- Manually saved private key paths are validated when you save them, not later on first connect

## Support

Contact me to collaborate.
