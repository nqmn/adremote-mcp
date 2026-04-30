# SSH Remote MCP Server

SSH remote access for MCP-compatible clients through Model Context Protocol (MCP).

## Quick Start

Use a virtual environment created by the same OS that will launch the MCP
server. Do not share one `venv` between Windows and WSL/Linux.

### Windows

1. **Install**:
   ```powershell
   .\install.ps1
   ```

2. **Add the MCP in Claude Desktop, Claude Code, or Codex**:
   ```json
   {
     "mcpServers": {
       "ssh-remote": {
         "command": "C:\\Users\\Intel\\Desktop\\adremote-mcp\\.venv-win\\Scripts\\python.exe",
         "args": [
           "C:\\Users\\Intel\\Desktop\\adremote-mcp\\ssh_mcp_server.py"
         ]
       }
     }
   }
   ```

   If you already have a Windows Python with `paramiko` and `mcp` installed,
   you can use that interpreter directly instead of `.venv-win`.

### WSL/Linux

1. **Install**:
   ```bash
   ./install.sh
   ```

2. **Add the MCP in Claude Desktop, Claude Code, or Codex**:
   ```json
   {
     "mcpServers": {
       "ssh-remote": {
         "command": "/home/user/adremote-mcp/.venv-linux/bin/python",
         "args": [
           "/home/user/adremote-mcp/ssh_mcp_server.py"
         ]
       }
     }
   }
   ```

   If the repo is accessed through WSL from the Windows drive, use the WSL path:
   ```json
   {
     "mcpServers": {
       "ssh-remote": {
         "command": "/mnt/c/Users/Intel/Desktop/adremote-mcp/.venv-linux/bin/python",
         "args": [
           "/mnt/c/Users/Intel/Desktop/adremote-mcp/ssh_mcp_server.py"
         ]
       }
     }
   }
   ```

### Portable Launchers

You can also point an MCP client at the included launcher for the matching OS:

- Windows: `C:\Users\Intel\Desktop\adremote-mcp\run-ssh-mcp.cmd`
- WSL/Linux: `/path/to/adremote-mcp/run-ssh-mcp.sh`

The launchers prefer the OS-specific venv and then fall back to `python3` or
`python`. On Windows, `SSH_MCP_PYTHON` can be set to force a specific Python
interpreter.

For WSL/Linux clients, use `command: "/bin/sh"` with
`args: ["/path/to/adremote-mcp/run-ssh-mcp.sh"]` if the script is not marked
executable.

### Direct Run

After installing dependencies, you can run the server directly:

Windows:
```powershell
.\.venv-win\Scripts\python.exe .\ssh_mcp_server.py
```

WSL/Linux:
```bash
./.venv-linux/bin/python ssh_mcp_server.py
```

### Automatic Setup

Download this repo, run Claude or Codex, and ask it to add this folder as a
global MCP server for your current OS. After that, you can use it directly from
chat.

### Troubleshooting

If Windows reports:

```text
No Python at '"/usr/bin\python.exe'
```

the MCP is pointing at a venv created by WSL/Linux. Create a Windows venv with
`.\install.ps1` and update the MCP command to `.venv-win\Scripts\python.exe`.

## Features

- Works with MCP-compatible clients on Windows and Linux
- Connect to remote servers via SSH
- Native SSH jump-host / bastion support
- Execute commands remotely
- Upload/download files via SFTP
- Manage multiple connections
- Health monitoring

## Usage Examples

### Connect with password:
```
Connect to 192.168.1.100 with username ubuntu and password mypass
```

or in shorter form:
```
ssh 192.168.1.100:22 ubuntu mypass
```

The MCP first tests the SSH connection with your username and password.
If the login works, it generates or installs an SSH key, saves the key-based credential locally, and does not save the password.
The password is only used the first time.

### Connect with password for a one-off session:
```
ssh 192.168.1.100:22 ubuntu mypass, save_credentials false
```
This keeps the live connection only. No reusable credential is saved and no automatic key bootstrap is attempted.

### Connect later using the saved name:
```
ssh saved-name
```
After the first successful setup, just use the saved credential name to connect again.

### Connect with an encrypted (passphrase-protected) private key:
```
Connect to 10.0.2.15 as ubuntu using private key ~/.ssh/id_ed25519 with passphrase mysecret
```
or via tool parameters:
```json
{
  "hostname": "10.0.2.15",
  "username": "ubuntu",
  "private_key_path": "~/.ssh/id_ed25519",
  "private_key_passphrase": "mysecret"
}
```
The passphrase is used only in memory and is never written to disk. If a saved credential points to an encrypted key, supply `private_key_passphrase` each time you call `ssh_connect_saved`.

### Connect through a jump host:
Use the `jump_host` object on `ssh_connect` or `ssh_save_credentials`:

```json
{
  "hostname": "10.0.2.15",
  "username": "ubuntu",
  "private_key_path": "~/.ssh/id_ed25519",
  "jump_host": {
    "hostname": "203.0.113.10",
    "username": "bastion",
    "private_key_path": "~/.ssh/id_ed25519",
    "port": 22
  }
}
```

Jump host keys can also be passphrase-protected — add `private_key_passphrase` inside the `jump_host` object.

This uses a native SSH tunnel to the target host and saved credentials retain the same jump-host configuration.
For reusable saved credentials, the jump host must use `private_key_path` rather than a password.

### Execute commands:
```
List files in /home directory on my server
Run 'top' command on the remote server
Execute script.py and monitor its log
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

Version `1.0.2` adds support for passphrase-protected (encrypted) private keys:

- `private_key_passphrase` accepted on `ssh_connect`, `ssh_connect_saved`, and `ssh_save_credentials`
- Applies to both the target host key and the jump host key
- The passphrase is used only in memory — it is never written to the credential store
- Clear error messages when a key is encrypted but no passphrase is supplied, or when the passphrase is wrong

Version `1.0.1` adds safer and more practical day-to-day SSH workflows:

- Direct logins still save reusable credentials by default, but `save_credentials=false` now cleanly opts out for password sessions too
- Saved credential flows now include connect, save, list, delete, and manual key setup helpers
- Host trust and file transfer rules are stricter, with local root restrictions and trust-on-first-use host pinning
- Native jump-host connections are supported for both live sessions and saved credentials
- Saved credentials are key-based, so no master password is required for normal use
- Manually saved private key paths are validated when you save them, not later on first connect

## Support

Contact me to collaborate.
