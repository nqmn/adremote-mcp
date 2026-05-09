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
- Direct execution for simple read-only commands such as `ls`, `pwd`, and `whoami`
- Plan-and-approve flow for non-trivial commands and remote file edits
- Full plan details shown immediately on creation — no extra lookup needed
- Read remote files and apply managed remote edits with verification and backups
- Upload/download files via SFTP
- Manage multiple connections
- Health monitoring
- Human-readable audit log via `ssh_read_audit_log`

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

### Managed SSH key bootstrap:

`ssh_setup_key_auth` no longer installs a key immediately. It now creates a
high-risk plan because it modifies remote `authorized_keys` and stores a local
credential. Review and approve that plan with:

- `ssh_setup_key_auth`
- `ssh_approve_plan`
- `ssh_execute_plan`

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
The passphrase is stored alongside the saved credential so future calls to `ssh_connect_saved` do not require it again. You can still supply `private_key_passphrase` on `ssh_connect_saved` to override the stored value for a single session.

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
Run `ls` in /home on the remote server
Run `pwd` on the remote server
Run `whoami` on the remote server
```

Simple read-only commands from the allowlist execute directly. Commands outside
that allowlist are blocked from direct execution and returned as plans that must
be reviewed and approved before they run.

Plans are stored locally so they survive MCP server restarts. Each plan expires
after 24 hours; expired plans must be recreated.

Use `ssh_get_plan` to retrieve the full stored plan body, including payload and
approval metadata, when the chat output no longer shows it.

Each stored plan also keeps a compact approval summary with:
- tool
- target
- action
- summary
- plan id

Clients can use that summary directly for permission prompts without fetching
the full plan body every time.

### Managed command plans:
Use these tools for commands outside the direct allowlist:

- `ssh_plan_command`
- `ssh_approve_plan`
- `ssh_execute_plan`
- `ssh_list_plans`
- `ssh_get_plan`
- `ssh_reject_plan`

Typical flow:
1. Create a command plan with `ssh_plan_command`
2. Review the returned risk and rollback details
3. Approve it with `ssh_approve_plan`
4. Execute it with `ssh_execute_plan`

### Remote file reads and edits:

Read a remote file directly:
```
Read /etc/nginx/nginx.conf on the server
```

For remote edits, use the managed edit lane:

- `ssh_read_file`
- `ssh_plan_edit`
- `ssh_approve_plan`
- `ssh_execute_plan`

`ssh_plan_edit` stores the current file hash, requires approval, and
`ssh_execute_plan` writes the new content only after approval. Before writing,
the server creates a timestamped `.ssh-mcp.bak.<timestamp>` backup and verifies
the post-write SHA256 hash.

### File transfers:
```
Upload local file.txt to /home/user/ on the server
Download /var/log/app.log from the server
```

`ssh_upload_file` now creates an approval-backed plan before writing to the
remote host. After approval, `ssh_execute_plan` uploads the file and verifies
the remote SHA256 hash. `ssh_download_file` remains a direct read path to local
allowed roots.

### Audit log:
```
Show me the audit log
Show last 10 audit events
Show only approved plans in the audit log
```

Use `ssh_read_audit_log` to view a human-readable history of all plan lifecycle events. Each entry shows the timestamp, event type, plan ID, kind, connection, risk level, and summary. Use `limit` to cap the number of entries and `event_filter` to narrow by event type (`plan_created`, `plan_approved`, `plan_rejected`, `plan_executed`, `plan_expired`).

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

Version `1.2.0` improves plan visibility and adds a readable audit log tool:

- All plan-creating tools (`ssh_execute`, `ssh_plan_command`, `ssh_plan_edit`, `ssh_upload_file`, `ssh_setup_key_auth`) now return full plan details including risk, rollback plan, and payload immediately on creation — no need to call `ssh_get_plan` separately
- New `ssh_read_audit_log` tool reads `.ssh_mcp_audit.jsonl` and formats it into a human-readable event history with timestamps, event labels, and extra context per entry
- `ssh_read_audit_log` supports `limit` (number of recent entries) and `event_filter` (narrow by event type)

Version `1.1.0` adds orchestration for non-trivial remote actions:

- `ssh_execute` now runs only a conservative allowlist of simple read-only commands directly
- Commands outside the allowlist are converted into plans that require approval before execution
- New tools support managed remote reads and edits: `ssh_read_file`, `ssh_plan_edit`, `ssh_approve_plan`, `ssh_execute_plan`, `ssh_list_plans`, and `ssh_reject_plan`
- `ssh_setup_key_auth` now creates an approval-backed plan before modifying remote `authorized_keys` or saving a credential
- `ssh_upload_file` now creates an approval-backed plan before writing a file to the remote host
- Approval-backed plans are now persisted locally and expire after 24 hours
- Audit events are appended to `.ssh_mcp_audit.jsonl` in the current workspace folder
- Each plan now stores a compact approval summary for low-token permission prompts
- Managed remote edits create a timestamped backup and verify the resulting file hash after writing

Version `1.0.3` persists the private key passphrase in saved credentials:

- `private_key_passphrase` is now stored in the credential file when saving via `ssh_connect` or `ssh_save_credentials`
- `ssh_connect_saved` uses the stored passphrase automatically — no need to supply it on every call
- Supplying `private_key_passphrase` on `ssh_connect_saved` overrides the stored value for that session only
- `ssh_list_saved_credentials` shows `private key (passphrase saved)` when a passphrase is stored

Version `1.0.2` adds support for passphrase-protected (encrypted) private keys:

- `private_key_passphrase` accepted on `ssh_connect`, `ssh_connect_saved`, and `ssh_save_credentials`
- Applies to both the target host key and the jump host key
- Clear error messages when a key is encrypted but no passphrase is supplied, or when the passphrase is wrong

Version `1.0.1` adds safer and more practical day-to-day SSH workflows:

- Direct logins still save reusable credentials by default, but `save_credentials=false` now cleanly opts out for password sessions too
- Saved credential flows now include connect, save, list, delete, and manual key setup helpers
- Host trust and file transfer rules are stricter, with local root restrictions and trust-on-first-use host pinning
- Native jump-host connections are supported for both live sessions and saved credentials
- Saved credentials are key-based, so no master password is required for normal use
- Manually saved private key paths are validated when you save them, not later on first connect

## Support

- GitHub: https://github.com/nqmn/adremote-mcp
- Email: mohdadil@live.com
