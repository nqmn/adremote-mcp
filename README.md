# SSH Remote MCP Server

SSH remote access for Claude Code through Model Context Protocol (MCP).

## Quick Start

1. **Install**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Configure Claude Desktop**:

   **For Claude Desktop App:**
   Add to `%APPDATA%\Claude\claude_desktop_config.json` (Windows) or `~/Library/Application Support/Claude/claude_desktop_config.json` (Mac):
   ```json
   {
     "mcpServers": {
       "ssh-remote": {
         "command": "python",
         "args": ["/absolute/path/to/ssh_mcp_server.py"]
       }
     }
   }
   ```

   **For Claude Code:**
   Add to your Claude Code MCP config:
   ```json
   {
     "ssh-remote": {
       "command": "python",
       "args": ["/path/to/ssh_mcp_server.py"]
     }
   }
   ```

3. **Restart Claude Desktop** and test:

   Just chat naturally with Claude:
   - "Connect to my server at 192.168.1.100 with username ubuntu and password mypass"
   - "List files in the home directory on my server"
   - "Upload file.txt to /home/ubuntu/ on the server"
   - "Run 'htop' command on my remote server"

## Features

- Connect to remote servers via SSH
- Execute commands remotely
- Upload/download files via SFTP
- Manage multiple connections
- Health monitoring

## Configuration Example

```json
{
  "mcpServers": {
    "ssh-remote": {
      "command": "python",
      "args": ["/absolute/path/to/ssh_mcp_server.py"]
    }
  }
}
```

## Usage Examples

### Connect with password:
```
Connect to 192.168.1.100 with username ubuntu and password mypass
```

### Connect with SSH key:
```
Connect to myserver.com using SSH key ~/.ssh/id_rsa as user admin
```

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

## Requirements

- Python 3.7+
- paramiko
- mcp

## Security

- Automatic host key acceptance
- Supports password and key authentication
- Connection timeouts enforced