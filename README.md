# SSH Remote MCP Server

SSH remote access for Claude Code through Model Context Protocol (MCP).

## Latest Update

Version `1.0.1` adds safer and more practical day-to-day SSH workflows:

- Direct password logins now bootstrap a local SSH key and save a reusable key-based credential automatically
- Saved credential flows now include connect, save, list, delete, and manual key setup helpers
- Host trust and file transfer rules are stricter, with local root restrictions and trust-on-first-use host pinning
- Saved credentials are key-based, so no master password is required for normal use

## Quick Start

1. **Install**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Set allowed local file roots**:
   By default, upload and download tools are restricted to the current working directory of the MCP server process. To allow additional directories, set `SSH_MCP_ALLOWED_LOCAL_ROOTS` before launching the server.

   Windows:
   ```powershell
   $env:SSH_MCP_ALLOWED_LOCAL_ROOTS="C:\allowed\downloads;C:\allowed\uploads"
   ```

   Linux/macOS:
   ```bash
   export SSH_MCP_ALLOWED_LOCAL_ROOTS="/allowed/downloads:/allowed/uploads"
   ```

3. **Optional: local credential memory**
   Saved credentials are stored at `~/.ssh_mcp_credentials.json`.
   New password-based connects and saves are treated as first-time bootstrap only: the MCP installs a generated SSH key on the server and saves the key-based credential for future logins.
   No master password is required because reusable saved credentials are stored as key-based logins, not password-backed entries.

4. **Configure Claude Desktop**:

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

5. **Restart Claude Desktop** and test:

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

## SSH Setup

### Recommended: use SSH keys

If you already use SSH keys, point the MCP at your existing private key. If not, you can prepare one manually:

1. Generate a key pair:
   ```bash
   ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa_ubuntu
   ```
2. Copy the public key to the server:
   ```bash
   ssh-copy-id -i ~/.ssh/id_rsa_ubuntu.pub username@server_ip
   ```
   Or manually:
   ```bash
   cat ~/.ssh/id_rsa_ubuntu.pub | ssh username@server_ip "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys"
   ```
3. Test the SSH connection:
   ```bash
   ssh -i ~/.ssh/id_rsa_ubuntu username@server_ip
   ```
4. Use the same key with the MCP:
   ```text
   Connect to my server 192.168.1.100 using SSH key ~/.ssh/id_rsa_ubuntu with username ubuntu
   ```

## Usage Examples

### Connect with password:
```
Connect to 192.168.1.100 with username ubuntu and password mypass
```
This now bootstraps a local SSH key automatically and saves a reusable key-based credential for later logins.

### Connect with SSH key:
```
Connect to myserver.com using SSH key ~/.ssh/id_rsa as user admin
```

### Connect with SSH key on a custom port:
```
Connect to server 10.0.0.50 port 2222 using SSH key ~/.ssh/id_rsa with username admin
```

### Connect to a new host explicitly:
```
Connect to myserver.com as user admin and trust_unknown_host true
```
This performs trust-on-first-use and pins the accepted host key in `~/.ssh_mcp_known_hosts`.

### Name multiple live connections:
```
Connect to production server 10.0.1.100 with key ~/.ssh/prod_key as user deploy, connection_name prod
Connect to staging server 10.0.1.200 with password stagingpass123 as user ubuntu, connection_name staging
```

### Save credentials locally:
```
Save SSH credentials locally with name prod-web for host 10.0.1.100, username deploy, and password mypass
```
If you provide a password, the MCP connects once, installs a generated SSH key, and saves only the key-based credential.

### Connect using saved credentials:
```
Connect using saved_credential_name prod-web
```

### Connect using the shortcut tool:
```
Use ssh_connect_saved with name prod-web
```

### Optional manual key setup after a password login:
```
Connect to 10.0.1.100 with username deploy and password mypass
Then use ssh_setup_key_auth with connection_name 10.0.1.100 and credential_name prod-web
```
This is now mostly useful when you want to control the saved credential name or rotate keys manually.

### Save during connect:
```
Connect to 10.0.1.100 with username deploy and password mypass, save_credentials true, credential_name prod-web
```
This saves a key-based credential named `prod-web`. The password is only used for the initial bootstrap.

### Auto-save direct logins:
```
Connect to 10.0.1.100 with username deploy and password mypass
Connect to 10.0.1.100 with username deploy and private key ~/.ssh/prod_key
```
Direct logins now save reusable credentials by default. The saved name defaults to `connection_name` if provided, otherwise `hostname`. Set `save_credentials=false` to opt out.

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

- Python 3.8+
- paramiko
- mcp

## Security

- Host key verification uses system `known_hosts` by default
- Unknown hosts are rejected unless `trust_unknown_host` is explicitly enabled
- `trust_unknown_host=true` performs trust-on-first-use and pins accepted keys in `~/.ssh_mcp_known_hosts`
- Supports password and key authentication
- Direct password and private-key login flows save reusable credentials by default
- New password-based credential flows automatically bootstrap a real SSH keypair and save the key for future logins
- `ssh_setup_key_auth` remains available for manual key rotation or custom naming after a live login
- Upload/download access is restricted to `SSH_MCP_ALLOWED_LOCAL_ROOTS`
- Saved credentials live in `~/.ssh_mcp_credentials.json`
- Legacy password-backed saved credentials are no longer supported; recreate them as key-based entries if needed
- Generated SSH keys live in `~/.ssh_mcp_keys`
- Use strong passwords if you still rely on password auth for first-time bootstrap
- Limit SSH access with firewall rules and prefer non-root users with `sudo`
- Connection timeouts enforced
