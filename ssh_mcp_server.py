#!/usr/bin/env python3
"""SSH MCP Server for remote SSH connections and file transfers."""

import asyncio
import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Union

import paramiko
from mcp.server import Server
from mcp.server.models import InitializationOptions
from mcp.server.stdio import stdio_server
from mcp.types import (
    EmbeddedResource,
    ImageContent,
    ServerCapabilities,
    TextContent,
    Tool,
    ToolsCapability,
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

DEFAULT_CONNECT_TIMEOUT = 10
DEFAULT_COMMAND_TIMEOUT = 30
DEFAULT_HEALTH_TIMEOUT = 5
DEFAULT_SAVE_DIRECT_CREDENTIALS = True
ENV_ALLOWED_LOCAL_ROOTS = "SSH_MCP_ALLOWED_LOCAL_ROOTS"
CREDENTIAL_STORE_FILE = ".ssh_mcp_credentials.json"
CREDENTIAL_STORE_VERSION = 1
KEY_STORE_DIR = ".ssh_mcp_keys"
HOST_KEY_STORE_FILE = ".ssh_mcp_known_hosts"


def _set_posix_permissions(path: Path, mode: int) -> None:
    if os.name != "posix":
        return
    try:
        os.chmod(path, mode)
    except FileNotFoundError:
        pass


def _ensure_file(path: Path, *, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.touch()
    _set_posix_permissions(path, mode)


def _ensure_directory(path: Path, *, mode: int = 0o700) -> None:
    path.mkdir(parents=True, exist_ok=True)
    _set_posix_permissions(path, mode)


def _write_secure_text(path: Path, content: str, *, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    _set_posix_permissions(path, mode)


@dataclass
class SSHConnection:
    """Represents an active SSH connection."""
    client: paramiko.SSHClient
    hostname: str
    username: str
    port: int
    jump_client: paramiko.SSHClient | None = None
    jump_description: str | None = None
    jump_host: Dict[str, Any] | None = None
    known_hosts_path: str | None = None
    connected: bool = False
    last_used: float = 0.0

    def __post_init__(self):
        self.last_used = time.time()


class CredentialStore:
    """Persist SSH credentials locally for reuse."""

    def __init__(self, store_path: Path):
        self.store_path = store_path
        self.store_path.parent.mkdir(parents=True, exist_ok=True)
        _set_posix_permissions(self.store_path, 0o600)

    def _read(self) -> Dict[str, Any]:
        if not self.store_path.exists():
            return {"version": CREDENTIAL_STORE_VERSION, "credentials": {}}

        data = json.loads(self.store_path.read_text(encoding="utf-8"))
        data.setdefault("version", CREDENTIAL_STORE_VERSION)
        data.setdefault("credentials", {})
        return data

    def _write(self, data: Dict[str, Any]) -> None:
        _write_secure_text(
            self.store_path,
            json.dumps(data, indent=2, sort_keys=True),
        )

    def save(self, name: str, payload: Dict[str, Any]) -> None:
        data = self._read()
        stored = dict(payload)

        if stored.get("password"):
            raise ValueError(
                "Password-backed saved credentials are no longer supported. "
                "Connect once with a password to bootstrap a key, or save a private key path."
            )

        data["credentials"][name] = stored
        self._write(data)

    def load(self, name: str) -> Dict[str, Any]:
        data = self._read()
        if name not in data["credentials"]:
            raise KeyError(f"Saved credential '{name}' not found")

        stored = dict(data["credentials"][name])
        if stored.get("password"):
            raise RuntimeError(
                f"Saved credential '{name}' uses a legacy password entry that is no longer supported. "
                "Delete it and save a key-based credential instead."
            )

        return stored

    def delete(self, name: str) -> None:
        data = self._read()
        if name not in data["credentials"]:
            raise KeyError(f"Saved credential '{name}' not found")
        del data["credentials"][name]
        self._write(data)

    def list_entries(self) -> List[Dict[str, Any]]:
        data = self._read()
        entries: List[Dict[str, Any]] = []
        for name, stored in sorted(data["credentials"].items()):
            entries.append(
                {
                    "name": name,
                    "hostname": stored.get("hostname"),
                    "username": stored.get("username"),
                    "port": stored.get("port", 22),
                    "jump_host": stored.get("jump_host"),
                    "has_password": bool(stored.get("password")),
                    "has_private_key_path": bool(stored.get("private_key_path")),
                    "has_private_key_passphrase": bool(stored.get("private_key_passphrase")),
                }
            )
        return entries


class SSHMCPServer:
    """MCP Server for SSH operations on remote Ubuntu servers."""

    def __init__(self):
        self.server = Server("ssh-mcp-server")
        self.connections: Dict[str, SSHConnection] = {}
        self.allowed_local_roots = self._load_allowed_local_roots()
        self.credential_store = CredentialStore(Path.home() / CREDENTIAL_STORE_FILE)
        self.host_key_store_path = Path.home() / HOST_KEY_STORE_FILE
        _ensure_file(self.host_key_store_path, mode=0o600)
        self.key_store_dir = Path.home() / KEY_STORE_DIR
        _ensure_directory(self.key_store_dir, mode=0o700)
        self.setup_tools()

    def _load_allowed_local_roots(self) -> List[Path]:
        """Load writable/readable local roots for file transfer tools."""
        configured_roots = os.environ.get(ENV_ALLOWED_LOCAL_ROOTS, "").strip()
        roots: List[Path] = []

        if configured_roots:
            for raw_root in configured_roots.split(os.pathsep):
                if not raw_root.strip():
                    continue
                roots.append(Path(raw_root).expanduser().resolve(strict=False))

        if not roots:
            roots.append(Path.cwd().resolve(strict=False))

        return roots

    def _allowed_roots_text(self) -> str:
        return ", ".join(str(root) for root in self.allowed_local_roots)

    def _validate_local_path(self, raw_path: str, *, require_exists: bool) -> Path:
        """Restrict local file access to explicitly allowed roots."""
        resolved = Path(raw_path).expanduser().resolve(strict=False)

        if require_exists and not resolved.exists():
            raise FileNotFoundError(f"Local file not found: {resolved}")

        for root in self.allowed_local_roots:
            try:
                resolved.relative_to(root)
                return resolved
            except ValueError:
                continue

        raise ValueError(
            "Local path is outside allowed roots. "
            f"Allowed roots: {self._allowed_roots_text()}"
        )

    async def _run_blocking(self, func, *args, **kwargs):
        """Run Paramiko's blocking calls off the event loop."""
        return await asyncio.to_thread(func, *args, **kwargs)

    async def _exec_command(
        self, client: paramiko.SSHClient, command: str, timeout: int
    ) -> tuple[str, str, int]:
        def run_command() -> tuple[str, str, int]:
            _, stdout, stderr = client.exec_command(command, timeout=timeout)
            stdout_text = stdout.read().decode("utf-8", errors="replace")
            stderr_text = stderr.read().decode("utf-8", errors="replace")
            exit_code = stdout.channel.recv_exit_status()
            return stdout_text, stderr_text, exit_code

        return await self._run_blocking(run_command)

    def _key_paths(self, key_name: str) -> tuple[Path, Path]:
        sanitized = "".join(
            char for char in key_name if char.isalnum() or char in ("-", "_", ".")
        ).strip(".")
        if not sanitized:
            raise ValueError("key_name must contain at least one alphanumeric character")
        # Preserve legacy filenames for already-safe names, but add a stable hash
        # when normalization would otherwise collapse distinct names together.
        if sanitized == key_name:
            key_filename = sanitized
        else:
            key_suffix = hashlib.sha256(key_name.encode("utf-8")).hexdigest()[:12]
            key_filename = f"{sanitized}-{key_suffix}"
        private_key_path = self.key_store_dir / key_filename
        public_key_path = self.key_store_dir / f"{key_filename}.pub"
        return private_key_path, public_key_path

    async def _generate_local_keypair(
        self, key_name: str, comment: str
    ) -> tuple[Path, Path]:
        private_key_path, public_key_path = self._key_paths(key_name)

        if private_key_path.exists() or public_key_path.exists():
            raise FileExistsError(f"Key '{key_name}' already exists in {self.key_store_dir}")

        def generate_keypair() -> tuple[Path, Path]:
            key = paramiko.RSAKey.generate(3072)
            key.write_private_key_file(str(private_key_path))
            os.chmod(private_key_path, 0o600)

            public_key = f"{key.get_name()} {key.get_base64()} {comment}\n"
            public_key_path.write_text(public_key, encoding="utf-8")
            return private_key_path, public_key_path

        return await self._run_blocking(generate_keypair)

    def _private_key_classes(self) -> List[Any]:
        return [
            key_class
            for key_class in (
                getattr(paramiko, "RSAKey", None),
                getattr(paramiko, "ECDSAKey", None),
                getattr(paramiko, "Ed25519Key", None),
            )
            if key_class is not None
        ]

    def _load_private_key(self, private_key_path: Path, passphrase: str | None = None):
        for key_class in self._private_key_classes():
            try:
                return key_class.from_private_key_file(
                    str(private_key_path), password=passphrase
                )
            except paramiko.PasswordRequiredException as exc:
                raise RuntimeError(
                    "Private key requires a passphrase — supply private_key_passphrase"
                ) from exc
            except paramiko.ssh_exception.SSHException as exc:
                if passphrase is not None and "not a valid" not in str(exc).lower():
                    raise RuntimeError(
                        "Failed to decrypt private key — check private_key_passphrase"
                    ) from exc
                continue
            except Exception:
                continue

        raise RuntimeError("Unable to load private key (unsupported format)")

    async def _ensure_local_keypair(
        self, key_name: str, comment: str
    ) -> tuple[Path, Path]:
        private_key_path, public_key_path = self._key_paths(key_name)

        if private_key_path.exists():
            if not public_key_path.exists():
                key = await self._run_blocking(self._load_private_key, private_key_path)
                public_key = f"{key.get_name()} {key.get_base64()} {comment}\n"
                await self._run_blocking(
                    _write_secure_text,
                    public_key_path,
                    public_key,
                    mode=0o644,
                )
            return private_key_path, public_key_path

        if public_key_path.exists():
            raise FileExistsError(
                f"Public key '{public_key_path}' exists without matching private key"
            )

        return await self._generate_local_keypair(key_name, comment)

    async def _install_public_key_on_remote(
        self, client: paramiko.SSHClient, public_key: str
    ) -> None:
        escaped_public_key = public_key.strip().replace("'", "'\"'\"'")
        install_command = (
            "umask 077 && mkdir -p ~/.ssh && touch ~/.ssh/authorized_keys && "
            f"grep -Fqx '{escaped_public_key}' ~/.ssh/authorized_keys || "
            f"printf '%s\\n' '{escaped_public_key}' >> ~/.ssh/authorized_keys"
        )
        _, stderr_text, exit_code = await self._exec_command(
            client, install_command, DEFAULT_COMMAND_TIMEOUT
        )
        if exit_code != 0:
            raise RuntimeError(
                f"Failed to install public key on remote host: {stderr_text.strip()}"
            )

    def _save_key_credential(
        self,
        credential_name: str,
        *,
        hostname: str,
        username: str,
        private_key_path: Path,
        port: int,
        known_hosts_path: str | None,
        private_key_passphrase: str | None = None,
        jump_host: Dict[str, Any] | None = None,
    ) -> None:
        stored_jump_host = None
        if jump_host:
            if jump_host.get("password"):
                raise ValueError(
                    "Saved credentials do not support password-backed jump hosts. "
                    "Use jump_host.private_key_path or connect without saving credentials."
                )
            stored_jump_host = {
                key: value
                for key, value in jump_host.items()
                if key != "password"
            }
        payload: Dict[str, Any] = {
            "hostname": hostname,
            "username": username,
            "private_key_path": str(private_key_path),
            "port": port,
            "known_hosts_path": known_hosts_path,
            "trust_unknown_host": False,
            "jump_host": stored_jump_host,
        }
        if private_key_passphrase:
            payload["private_key_passphrase"] = private_key_passphrase
        self.credential_store.save(credential_name, payload)

    async def _bootstrap_key_auth(
        self,
        *,
        client: paramiko.SSHClient,
        hostname: str,
        username: str,
        port: int,
        credential_name: str,
        key_name: str,
        key_comment: str,
        known_hosts_path: str | None,
        overwrite_saved_credential: bool,
        jump_host: Dict[str, Any] | None = None,
    ) -> Path:
        existing_credentials = {
            entry["name"] for entry in self.credential_store.list_entries()
        }
        if credential_name in existing_credentials and not overwrite_saved_credential:
            raise RuntimeError(
                f"Saved credential '{credential_name}' already exists. "
                "Pass overwrite_saved_credential=true to replace it."
            )

        private_key_path, public_key_path = await self._ensure_local_keypair(
            key_name, key_comment
        )
        public_key = await self._run_blocking(
            lambda: public_key_path.read_text(encoding="utf-8")
        )
        await self._install_public_key_on_remote(client, public_key)
        self._save_key_credential(
            credential_name,
            hostname=hostname,
            username=username,
            private_key_path=private_key_path,
            port=port,
            known_hosts_path=known_hosts_path,
            jump_host=jump_host,
        )
        return private_key_path

    def _normalize_jump_host(self, jump_host: Any) -> Dict[str, Any] | None:
        if jump_host is None:
            return None
        if not isinstance(jump_host, dict):
            raise ValueError("jump_host must be an object")

        normalized = {
            key: value
            for key, value in jump_host.items()
            if value is not None
        }
        hostname = normalized.get("hostname")
        username = normalized.get("username")
        if not hostname or not username:
            raise ValueError("jump_host.hostname and jump_host.username are required")

        normalized["port"] = int(normalized.get("port", 22))

        if not normalized.get("password") and not normalized.get("private_key_path"):
            raise ValueError(
                "jump_host requires either password or private_key_path"
            )

        return normalized

    async def _connect_with_auth(
        self,
        client: paramiko.SSHClient,
        *,
        hostname: str,
        port: int,
        username: str,
        password: str | None,
        private_key_path: str | None,
        private_key_passphrase: str | None = None,
        sock: Any = None,
    ) -> None:
        if private_key_path:
            expanded_private_key_path = Path(private_key_path).expanduser()
            if not expanded_private_key_path.exists():
                raise FileNotFoundError(
                    f"Private key file not found: {expanded_private_key_path}"
                )
            key = await self._run_blocking(
                self._load_private_key, expanded_private_key_path, private_key_passphrase
            )
            await self._run_blocking(
                client.connect,
                hostname,
                port=port,
                username=username,
                pkey=key,
                timeout=DEFAULT_CONNECT_TIMEOUT,
                allow_agent=False,
                look_for_keys=False,
                sock=sock,
            )
            return

        if password:
            await self._run_blocking(
                client.connect,
                hostname,
                port=port,
                username=username,
                password=password,
                timeout=DEFAULT_CONNECT_TIMEOUT,
                allow_agent=False,
                look_for_keys=False,
                sock=sock,
            )
            return

        raise ValueError("Either password or private_key_path must be provided")

    async def _open_ssh_clients(
        self,
        *,
        hostname: str,
        port: int,
        username: str,
        password: str | None,
        private_key_path: str | None,
        private_key_passphrase: str | None = None,
        known_hosts_path: str | None,
        trust_unknown_host: bool,
        jump_host: Dict[str, Any] | None,
    ) -> tuple[paramiko.SSHClient, paramiko.SSHClient | None, str | None]:
        jump_client: paramiko.SSHClient | None = None
        client: paramiko.SSHClient | None = None
        jump_description: str | None = None

        try:
            if jump_host:
                jump_client = self._build_client(known_hosts_path, trust_unknown_host)
                await self._connect_with_auth(
                    jump_client,
                    hostname=jump_host["hostname"],
                    port=jump_host["port"],
                    username=jump_host["username"],
                    password=jump_host.get("password"),
                    private_key_path=jump_host.get("private_key_path"),
                    private_key_passphrase=jump_host.get("private_key_passphrase"),
                )
                if trust_unknown_host:
                    await self._run_blocking(
                        self._persist_trusted_host_keys, jump_client
                    )

                jump_description = (
                    f"{jump_host['username']}@{jump_host['hostname']}:{jump_host['port']}"
                )
                transport = jump_client.get_transport()
                if transport is None or not transport.is_active():
                    raise RuntimeError("Jump host transport is not active")

                client = self._build_client(known_hosts_path, trust_unknown_host)
                jump_channel = await self._run_blocking(
                    transport.open_channel,
                    "direct-tcpip",
                    (hostname, port),
                    ("127.0.0.1", 0),
                )
                await self._connect_with_auth(
                    client,
                    hostname=hostname,
                    port=port,
                    username=username,
                    password=password,
                    private_key_path=private_key_path,
                    private_key_passphrase=private_key_passphrase,
                    sock=jump_channel,
                )
                if trust_unknown_host:
                    await self._run_blocking(self._persist_trusted_host_keys, client)
                return client, jump_client, jump_description

            client = self._build_client(known_hosts_path, trust_unknown_host)
            await self._connect_with_auth(
                client,
                hostname=hostname,
                port=port,
                username=username,
                password=password,
                private_key_path=private_key_path,
                private_key_passphrase=private_key_passphrase,
            )
            if trust_unknown_host:
                await self._run_blocking(self._persist_trusted_host_keys, client)
            return client, None, None
        except Exception:
            if client is not None:
                try:
                    client.close()
                except Exception:
                    pass
            if jump_client is not None:
                try:
                    jump_client.close()
                except Exception:
                    pass
            raise

    def _build_client(self, known_hosts_path: str | None, trust_unknown_host: bool):
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.load_host_keys(str(self.host_key_store_path))
        if known_hosts_path:
            client.load_host_keys(str(Path(known_hosts_path).expanduser()))
        if trust_unknown_host:
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        else:
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
        return client

    def _persist_trusted_host_keys(self, client: paramiko.SSHClient) -> None:
        client.save_host_keys(str(self.host_key_store_path))

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
                                "description": "SSH password for first-time bootstrap when no private key is available"
                            },
                            "private_key_path": {
                                "type": "string",
                                "description": "Path to private key file (optional)"
                            },
                            "private_key_passphrase": {
                                "type": "string",
                                "description": "Passphrase for an encrypted private key. Stored in saved credentials when save_credentials is true."
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
                            },
                            "known_hosts_path": {
                                "type": "string",
                                "description": "Optional path to a known_hosts file to trust in addition to system host keys"
                            },
                            "trust_unknown_host": {
                                "type": "boolean",
                                "description": "Allow connecting to hosts not present in known_hosts. Defaults to false.",
                                "default": False
                            },
                            "saved_credential_name": {
                                "type": "string",
                                "description": "Load connection details from a saved local credential entry"
                            },
                            "save_credentials": {
                                "type": "boolean",
                                "description": "Persist a reusable local credential after a successful connect. Defaults to true for direct logins with password or private key. Password logins are converted into saved key-based credentials.",
                                "default": DEFAULT_SAVE_DIRECT_CREDENTIALS
                            },
                            "credential_name": {
                                "type": "string",
                                "description": "Name to use when saving credentials locally. Defaults to connection_name or hostname."
                            },
                            "jump_host": {
                                "type": "object",
                                "description": "Optional SSH jump host (bastion) used to reach the target via native SSH tunneling",
                                "properties": {
                                    "hostname": {
                                        "type": "string",
                                        "description": "Jump host hostname or IP address"
                                    },
                                    "username": {
                                        "type": "string",
                                        "description": "Jump host SSH username"
                                    },
                                    "password": {
                                        "type": "string",
                                        "description": "Jump host SSH password"
                                    },
                                    "private_key_path": {
                                        "type": "string",
                                        "description": "Path to the jump host private key"
                                    },
                                    "private_key_passphrase": {
                                        "type": "string",
                                        "description": "Passphrase for an encrypted jump host private key. Never stored."
                                    },
                                    "port": {
                                        "type": "integer",
                                        "description": "Jump host SSH port (default: 22)",
                                        "default": 22
                                    }
                                }
                            }
                        }
                    }
                ),
                Tool(
                    name="ssh_connect_saved",
                    description="Connect to a remote server using a saved local SSH credential name",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "name": {
                                "type": "string",
                                "description": "Saved credential name to use for the connection"
                            },
                            "connection_name": {
                                "type": "string",
                                "description": "Optional active connection name override"
                            },
                            "private_key_passphrase": {
                                "type": "string",
                                "description": "Passphrase override for the saved credential's encrypted private key. If the saved credential already has a passphrase, this overrides it for this session only."
                            }
                        },
                        "required": ["name"]
                    }
                ),
                Tool(
                    name="ssh_setup_key_auth",
                    description="Generate a local SSH keypair, install the public key on the remote server, and save a key-based credential for future connections",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "connection_name": {
                                "type": "string",
                                "description": "Existing active SSH connection that authenticated with a password"
                            },
                            "credential_name": {
                                "type": "string",
                                "description": "Saved credential name for future key-based logins"
                            },
                            "key_name": {
                                "type": "string",
                                "description": "Local key filename stem. Defaults to credential_name or connection_name."
                            },
                            "key_comment": {
                                "type": "string",
                                "description": "Comment appended to the generated public key"
                            },
                            "overwrite_saved_credential": {
                                "type": "boolean",
                                "description": "Overwrite an existing saved credential with the same credential_name",
                                "default": False
                            }
                        },
                        "required": ["connection_name"]
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
                    description="Upload a local file from an allowed local root to the remote server via SFTP",
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
                    description="Download a remote file to an allowed local root via SFTP",
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
                    name="ssh_save_credentials",
                    description="Save SSH credentials locally under a reusable name. If a password is provided, the server is contacted once to bootstrap a key and only the generated key credential is saved.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "name": {
                                "type": "string",
                                "description": "Saved credential name"
                            },
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
                                "description": "SSH password for first-time bootstrap when no private key is available"
                            },
                            "private_key_path": {
                                "type": "string",
                                "description": "Path to private key file (optional)"
                            },
                            "private_key_passphrase": {
                                "type": "string",
                                "description": "Passphrase for an encrypted private key. Stored alongside the credential."
                            },
                            "port": {
                                "type": "integer",
                                "description": "SSH port (default: 22)",
                                "default": 22
                            },
                            "known_hosts_path": {
                                "type": "string",
                                "description": "Optional path to an extra known_hosts file"
                            },
                            "trust_unknown_host": {
                                "type": "boolean",
                                "description": "Allow connecting to hosts not present in known_hosts. Defaults to false.",
                                "default": False
                            },
                            "jump_host": {
                                "type": "object",
                                "description": "Optional SSH jump host (bastion) used to reach the target via native SSH tunneling",
                                "properties": {
                                    "hostname": {
                                        "type": "string",
                                        "description": "Jump host hostname or IP address"
                                    },
                                    "username": {
                                        "type": "string",
                                        "description": "Jump host SSH username"
                                    },
                                    "password": {
                                        "type": "string",
                                        "description": "Jump host SSH password"
                                    },
                                    "private_key_path": {
                                        "type": "string",
                                        "description": "Path to the jump host private key"
                                    },
                                    "private_key_passphrase": {
                                        "type": "string",
                                        "description": "Passphrase for an encrypted jump host private key. Never stored."
                                    },
                                    "port": {
                                        "type": "integer",
                                        "description": "Jump host SSH port (default: 22)",
                                        "default": 22
                                    }
                                }
                            }
                        },
                        "required": ["name", "hostname", "username"]
                    }
                ),
                Tool(
                    name="ssh_list_saved_credentials",
                    description="List saved local SSH credential entries",
                    inputSchema={
                        "type": "object",
                        "properties": {}
                    }
                ),
                Tool(
                    name="ssh_delete_saved_credentials",
                    description="Delete a saved local SSH credential entry",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "name": {
                                "type": "string",
                                "description": "Saved credential name to delete"
                            }
                        },
                        "required": ["name"]
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
        async def call_tool(
            name: str, arguments: Dict[str, Any] | None
        ) -> List[Union[TextContent, ImageContent, EmbeddedResource]]:
            arguments = arguments or {}
            try:
                if name == "ssh_connect":
                    return await self._ssh_connect(arguments)
                elif name == "ssh_connect_saved":
                    return await self._ssh_connect_saved(arguments)
                elif name == "ssh_execute":
                    return await self._ssh_execute(arguments)
                elif name == "ssh_setup_key_auth":
                    return await self._ssh_setup_key_auth(arguments)
                elif name == "ssh_upload_file":
                    return await self._ssh_upload_file(arguments)
                elif name == "ssh_download_file":
                    return await self._ssh_download_file(arguments)
                elif name == "ssh_save_credentials":
                    return await self._ssh_save_credentials(arguments)
                elif name == "ssh_list_saved_credentials":
                    return await self._ssh_list_saved_credentials(arguments)
                elif name == "ssh_delete_saved_credentials":
                    return await self._ssh_delete_saved_credentials(arguments)
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
        saved_credential_name = args.get("saved_credential_name")
        credential_data: Dict[str, Any] = {}
        if saved_credential_name:
            try:
                credential_data = self.credential_store.load(saved_credential_name)
            except KeyError as e:
                return [TextContent(type="text", text=str(e))]
            except Exception as e:
                return [TextContent(
                    type="text",
                    text=f"Failed to load saved credential: {str(e)}",
                )]

        merged = dict(credential_data)
        merged.update({key: value for key, value in args.items() if value is not None})

        hostname = merged.get("hostname")
        username = merged.get("username")
        if not hostname or not username:
            return [TextContent(
                type="text",
                text="hostname and username are required unless provided by saved_credential_name",
            )]

        password = merged.get("password")
        private_key_path = merged.get("private_key_path")
        private_key_passphrase = merged.get("private_key_passphrase")
        port = merged.get("port", 22)
        connection_name = merged.get("connection_name", hostname)
        known_hosts_path = merged.get("known_hosts_path")
        trust_unknown_host = merged.get("trust_unknown_host", False)
        try:
            jump_host = self._normalize_jump_host(merged.get("jump_host"))
        except ValueError as e:
            return [TextContent(type="text", text=str(e))]
        jump_host_uses_password = bool(jump_host and jump_host.get("password"))
        direct_credentials_provided = (
            bool(args.get("password")) or bool(args.get("private_key_path"))
        )
        if "save_credentials" in args:
            save_credentials = bool(args.get("save_credentials"))
        else:
            save_credentials = (
                DEFAULT_SAVE_DIRECT_CREDENTIALS
                and direct_credentials_provided
                and not saved_credential_name
            )
        if jump_host_uses_password:
            save_credentials = False
        credential_name = args.get("credential_name") or connection_name
        used_password_auth = bool(password) and not private_key_path

        if connection_name in self.connections:
            return [TextContent(type="text", text=f"Connection '{connection_name}' already exists")]

        try:
            client, jump_client, jump_description = await self._open_ssh_clients(
                hostname=hostname,
                port=port,
                username=username,
                password=password,
                private_key_path=private_key_path,
                private_key_passphrase=private_key_passphrase,
                known_hosts_path=known_hosts_path,
                trust_unknown_host=trust_unknown_host,
                jump_host=jump_host,
            )

            # Test the connection
            try:
                test_output, _, exit_code = await self._exec_command(
                    client, "echo 'Connection test'", DEFAULT_HEALTH_TIMEOUT
                )
                if exit_code != 0 or test_output.strip() != "Connection test":
                    logger.warning(f"Connection test failed for {hostname}")
            except Exception as e:
                logger.warning(f"Connection test warning for {hostname}: {str(e)}")

            connection = SSHConnection(
                client=client,
                hostname=hostname,
                username=username,
                port=port,
                jump_client=jump_client,
                jump_description=jump_description,
                jump_host=jump_host,
                known_hosts_path=known_hosts_path,
                connected=True
            )

            self.connections[connection_name] = connection

            status_suffix = ""
            if used_password_auth and save_credentials:
                bootstrap_credential_name = (
                    saved_credential_name
                    or args.get("credential_name")
                    or (credential_name if save_credentials else f"{username}@{hostname}:{port}")
                )
                try:
                    await self._bootstrap_key_auth(
                        client=client,
                        hostname=hostname,
                        username=username,
                        port=port,
                        credential_name=bootstrap_credential_name,
                        key_name=bootstrap_credential_name,
                        key_comment=f"{username}@{hostname} via ssh-mcp",
                        known_hosts_path=known_hosts_path,
                        overwrite_saved_credential=True,
                        jump_host=jump_host,
                    )
                    status_suffix = (
                        f" Installed SSH public key and saved key-based credential "
                        f"'{bootstrap_credential_name}'. Future logins can use "
                        f"ssh_connect_saved name={bootstrap_credential_name}."
                    )
                except Exception as e:
                    status_suffix = (
                        f" Automatic key bootstrap failed: {str(e)}. "
                        "The live connection is still available, but future saved logins "
                        "will not use key auth until bootstrap succeeds."
                    )
            elif used_password_auth:
                status_suffix = (
                    " Password authentication was used for this live session only. "
                    "No reusable credential was saved."
                )
                if jump_host_uses_password:
                    status_suffix = (
                        " Password-backed jump host authentication was used for this "
                        "live session only. No reusable credential was saved."
                    )
            elif save_credentials:
                self._save_key_credential(
                    credential_name,
                    hostname=hostname,
                    username=username,
                    private_key_path=private_key_path,
                    port=port,
                    known_hosts_path=known_hosts_path,
                    private_key_passphrase=private_key_passphrase,
                    jump_host=jump_host,
                )
                passphrase_note = " Passphrase saved." if private_key_passphrase else ""
                status_suffix = f" Saved key-based credential '{credential_name}' locally.{passphrase_note}"

            if jump_description:
                status_suffix += f" Connected through jump host {jump_description}."

            return [TextContent(
                type="text",
                text=(
                    f"Successfully connected to {hostname}:{port} as {username} "
                    f"(connection: {connection_name})"
                    + status_suffix
                )
            )]

        except paramiko.AuthenticationException:
            return [TextContent(type="text", text="Authentication failed - check username/password or key")]
        except paramiko.BadHostKeyException as e:
            return [TextContent(
                type="text",
                text=(
                    f"Host key verification failed for {hostname}: {str(e)}. "
                    "Update your known_hosts entry or pass trust_unknown_host=true to trust on first use and pin the host key locally."
                ),
            )]
        except FileNotFoundError as e:
            return [TextContent(type="text", text=str(e))]
        except paramiko.SSHException as e:
            return [TextContent(
                type="text",
                text=(
                    f"SSH connection failed: {str(e)}. "
                    "If this is a new host, add it to known_hosts or pass trust_unknown_host=true to pin it locally."
                ),
            )]
        except Exception as e:
            return [TextContent(type="text", text=f"Failed to connect: {str(e)}")]

    async def _ssh_connect_saved(self, args: Dict[str, Any]) -> List[TextContent]:
        """Connect using a saved credential entry."""
        connect_args: Dict[str, Any] = {
            "saved_credential_name": args["name"],
        }
        if args.get("connection_name"):
            connect_args["connection_name"] = args["connection_name"]
        if args.get("private_key_passphrase"):
            connect_args["private_key_passphrase"] = args["private_key_passphrase"]
        return await self._ssh_connect(connect_args)

    async def _ssh_setup_key_auth(self, args: Dict[str, Any]) -> List[TextContent]:
        """Bootstrap SSH key authentication for an active connection."""
        connection_name = args["connection_name"]
        if connection_name not in self.connections:
            return [TextContent(type="text", text=f"Connection '{connection_name}' not found")]

        connection = self.connections[connection_name]
        if not connection.connected:
            return [TextContent(type="text", text=f"Connection '{connection_name}' is not active")]

        credential_name = args.get("credential_name", connection_name)
        key_name = args.get("key_name", credential_name)
        key_comment = args.get(
            "key_comment", f"{connection.username}@{connection.hostname} via ssh-mcp"
        )
        overwrite_saved_credential = bool(args.get("overwrite_saved_credential", False))

        existing_credentials = {
            entry["name"] for entry in self.credential_store.list_entries()
        }
        if credential_name in existing_credentials and not overwrite_saved_credential:
            return [TextContent(
                type="text",
                text=(
                    f"Saved credential '{credential_name}' already exists. "
                    "Pass overwrite_saved_credential=true to replace it."
                ),
            )]

        try:
            await self._bootstrap_key_auth(
                client=connection.client,
                hostname=connection.hostname,
                username=connection.username,
                port=connection.port,
                credential_name=credential_name,
                key_name=key_name,
                key_comment=key_comment,
                known_hosts_path=connection.known_hosts_path,
                overwrite_saved_credential=overwrite_saved_credential,
                jump_host=connection.jump_host,
            )

            return [TextContent(
                type="text",
                text=(
                    f"Installed SSH public key on {connection.hostname} and saved "
                    f"key-based credential '{credential_name}'. Future logins can use "
                    f"ssh_connect_saved name={credential_name}."
                ),
            )]
        except Exception as e:
            return [TextContent(type="text", text=f"Failed to set up key auth: {str(e)}")]

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

            stdout_text, stderr_text, exit_code = await self._exec_command(
                connection.client, command, timeout
            )

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
            source_path = self._validate_local_path(local_path, require_exists=True)

            # Update last used timestamp
            connection.last_used = time.time()

            def upload_file() -> None:
                sftp = connection.client.open_sftp()
                try:
                    sftp.put(str(source_path), remote_path)
                finally:
                    sftp.close()

            await self._run_blocking(upload_file)

            return [TextContent(
                type="text",
                text=f"Successfully uploaded {source_path} to {remote_path} on {connection.hostname}"
            )]

        except FileNotFoundError:
            return [TextContent(type="text", text=f"Local file not found: {local_path}")]
        except ValueError as e:
            return [TextContent(type="text", text=str(e))]
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
            target_path = self._validate_local_path(local_path, require_exists=False)

            # Update last used timestamp
            connection.last_used = time.time()

            # Create local directory if it doesn't exist
            local_dir = target_path.parent
            local_dir.mkdir(parents=True, exist_ok=True)

            def download_file() -> None:
                sftp = connection.client.open_sftp()
                try:
                    sftp.get(remote_path, str(target_path))
                finally:
                    sftp.close()

            await self._run_blocking(download_file)

            return [TextContent(
                type="text",
                text=f"Successfully downloaded {remote_path} to {target_path} from {connection.hostname}"
            )]

        except ValueError as e:
            return [TextContent(type="text", text=str(e))]
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
            await self._run_blocking(connection.client.close)
            if connection.jump_client is not None:
                await self._run_blocking(connection.jump_client.close)
            connection.connected = False
            del self.connections[connection_name]

            return [TextContent(
                type="text",
                text=f"Disconnected from {connection.hostname} (connection: {connection_name})"
            )]

        except Exception as e:
            return [TextContent(type="text", text=f"Failed to disconnect: {str(e)}")]

    async def _ssh_save_credentials(self, args: Dict[str, Any]) -> List[TextContent]:
        """Save SSH credentials locally."""
        name = args["name"]
        hostname = args["hostname"]
        username = args["username"]
        password = args.get("password")
        private_key_path = args.get("private_key_path")
        port = args.get("port", 22)
        known_hosts_path = args.get("known_hosts_path")
        trust_unknown_host = args.get("trust_unknown_host", False)
        try:
            jump_host = self._normalize_jump_host(args.get("jump_host"))
        except ValueError as e:
            return [TextContent(type="text", text=str(e))]
        if jump_host and jump_host.get("password"):
            return [TextContent(
                type="text",
                text=(
                    "Saved credentials do not support password-backed jump hosts. "
                    "Use jump_host.private_key_path or connect with ssh_connect for a live session only."
                ),
            )]

        if not password and not private_key_path:
            return [TextContent(
                type="text",
                text="Either password or private_key_path must be provided to save credentials",
            )]

        private_key_passphrase = args.get("private_key_passphrase")

        try:
            if private_key_path:
                private_key = Path(private_key_path).expanduser()
                if not private_key.exists():
                    return [TextContent(
                        type="text",
                        text=f"Private key file not found: {private_key}",
                    )]

                try:
                    await self._run_blocking(
                        self._load_private_key, private_key, private_key_passphrase
                    )
                except RuntimeError as e:
                    return [TextContent(type="text", text=str(e))]

                self._save_key_credential(
                    name,
                    hostname=hostname,
                    username=username,
                    private_key_path=private_key.resolve(strict=False),
                    port=port,
                    known_hosts_path=known_hosts_path,
                    private_key_passphrase=private_key_passphrase,
                    jump_host=jump_host,
                )
                passphrase_note = " Passphrase saved." if private_key_passphrase else ""
                return [TextContent(
                    type="text",
                    text=(
                        f"Saved key-based credential '{name}' locally in "
                        f"{self.credential_store.store_path}.{passphrase_note}"
                    ),
                )]

            client = None
            jump_client = None
            try:
                client, jump_client, _ = await self._open_ssh_clients(
                    hostname=hostname,
                    port=port,
                    username=username,
                    password=password,
                    private_key_path=None,
                    known_hosts_path=known_hosts_path,
                    trust_unknown_host=trust_unknown_host,
                    jump_host=jump_host,
                )
                await self._bootstrap_key_auth(
                    client=client,
                    hostname=hostname,
                    username=username,
                    port=port,
                    credential_name=name,
                    key_name=name,
                    key_comment=f"{username}@{hostname} via ssh-mcp",
                    known_hosts_path=known_hosts_path,
                    overwrite_saved_credential=True,
                    jump_host=jump_host,
                )
            finally:
                if client is not None:
                    await self._run_blocking(client.close)
                if jump_client is not None:
                    await self._run_blocking(jump_client.close)
        except paramiko.AuthenticationException:
            return [TextContent(type="text", text="Authentication failed - check username/password or key")]
        except paramiko.BadHostKeyException as e:
            return [TextContent(
                type="text",
                text=(
                    f"Host key verification failed for {hostname}: {str(e)}. "
                    "Update your known_hosts entry or pass trust_unknown_host=true to trust on first use and pin the host key locally."
                ),
            )]
        except paramiko.SSHException as e:
            return [TextContent(
                type="text",
                text=(
                    f"SSH connection failed: {str(e)}. "
                    "If this is a new host, add it to known_hosts or pass trust_unknown_host=true to pin it locally."
                ),
            )]
        except Exception as e:
            return [TextContent(
                type="text",
                text=f"Unable to save credentials: {str(e)}",
            )]

        return [TextContent(
            type="text",
            text=(
                f"Saved key-based credential '{name}' locally in "
                f"{self.credential_store.store_path}. A password was used only to "
                "bootstrap the generated SSH key."
            ),
        )]

    async def _ssh_list_saved_credentials(self, args: Dict[str, Any]) -> List[TextContent]:
        """List saved SSH credentials."""
        entries = self.credential_store.list_entries()
        if not entries:
            return [TextContent(type="text", text="No saved SSH credentials")]

        lines = [f"Saved SSH credentials ({self.credential_store.store_path}):"]
        for entry in entries:
            if entry["has_password"]:
                auth_mode = "legacy password entry (unsupported)"
            elif entry.get("has_private_key_passphrase"):
                auth_mode = "private key (passphrase saved)"
            else:
                auth_mode = "private key"
            jump_host = entry.get("jump_host")
            jump_suffix = ""
            if jump_host:
                jump_suffix = (
                    f" via {jump_host.get('username')}@{jump_host.get('hostname')}:"
                    f"{jump_host.get('port', 22)}"
                )
            lines.append(
                f"- {entry['name']}: {entry['username']}@{entry['hostname']}:{entry['port']} "
                f"({auth_mode}){jump_suffix}"
            )

        return [TextContent(type="text", text="\n".join(lines))]

    async def _ssh_delete_saved_credentials(self, args: Dict[str, Any]) -> List[TextContent]:
        """Delete saved SSH credentials."""
        name = args["name"]
        try:
            self.credential_store.delete(name)
        except KeyError as e:
            return [TextContent(type="text", text=str(e))]

        return [TextContent(type="text", text=f"Deleted saved credential '{name}'")]

    async def _ssh_list_connections(self, args: Dict[str, Any]) -> List[TextContent]:
        """List all active SSH connections."""
        if not self.connections:
            return [TextContent(type="text", text="No active SSH connections")]

        result = (
            "Active SSH Connections:\n"
            f"Allowed local file roots: {self._allowed_roots_text()}\n"
        )
        for name, conn in self.connections.items():
            status = "Connected" if conn.connected else "Disconnected"
            last_used = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(conn.last_used))
            jump_suffix = f" via {conn.jump_description}" if conn.jump_description else ""
            result += (
                f"- {name}: {conn.username}@{conn.hostname}:{conn.port}{jump_suffix} "
                f"({status}) - Last used: {last_used}\n"
            )

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
            output, _, exit_code = await self._exec_command(
                connection.client, "echo 'health_check'", DEFAULT_HEALTH_TIMEOUT
            )
            output = output.strip()

            if exit_code == 0 and output == "health_check":
                uptime_output, _, _ = await self._exec_command(
                    connection.client, "uptime", DEFAULT_HEALTH_TIMEOUT
                )
                uptime_output = uptime_output.strip()

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
                    server_version="1.0.2",
                    capabilities=ServerCapabilities(
                        tools=ToolsCapability()
                    )
                )
            )

async def async_main():
    """Async entry point."""
    server = SSHMCPServer()
    await server.run()

def main():
    """Console script entry point."""
    asyncio.run(async_main())

if __name__ == "__main__":
    main()
