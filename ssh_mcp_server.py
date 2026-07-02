#!/usr/bin/env python3
"""SSH MCP Server for remote SSH connections and file transfers."""

import asyncio
import hashlib
import json
import logging
import os
import shlex
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
PLAN_STORE_FILE = ".ssh_mcp_plans.json"
AUDIT_LOG_FILE = ".ssh_mcp_audit.jsonl"
PLAN_STORE_VERSION = 1
DEFAULT_PLAN_TTL_SECONDS = 24 * 60 * 60
PLAN_STATUS_DRAFT = "draft"
PLAN_STATUS_APPROVED = "approved"
PLAN_STATUS_EXECUTED = "executed"
PLAN_STATUS_REJECTED = "rejected"
PLAN_KIND_COMMAND = "command"
PLAN_KIND_FILE_EDIT = "file_edit"
PLAN_KIND_UPLOAD = "upload"
PLAN_KIND_KEY_AUTH = "key_auth"
CONFIG_FILE = "config.json"
AUTO_MODE_ENABLED = "enabled"
AUTO_MODE_DISABLED = "disabled"
SUPPORTED_AUTO_MODES = {AUTO_MODE_ENABLED, AUTO_MODE_DISABLED}
SAFE_DIRECT_COMMANDS = {
    "date",
    "hostname",
    "id",
    "ls",
    "pwd",
    "uname",
    "uptime",
    "whoami",
}
HIGH_RISK_COMMAND_PREFIXES = {
    "apt",
    "apt-get",
    "chmod",
    "chown",
    "cp",
    "curl",
    "dnf",
    "docker",
    "git",
    "install",
    "kubectl",
    "mkdir",
    "mv",
    "npm",
    "pip",
    "python",
    "python3",
    "rm",
    "rmdir",
    "sed",
    "service",
    "systemctl",
    "tee",
    "touch",
    "vi",
    "vim",
    "wget",
    "yum",
}
SHELL_META_TOKENS = ("&&", "||", "|", ";", ">", "<", "$(", "`", "\n", "\r")


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


@dataclass
class ExecutionPlan:
    """Represents a managed command or remote file edit."""
    plan_id: str
    kind: str
    connection_name: str
    status: str
    approval_required: bool
    risk: str
    operational_risk: str
    approval_summary: Dict[str, str]
    summary: str
    rollback_plan: str
    created_at: float
    expires_at: float
    payload: Dict[str, Any]
    verification: str | None = None
    approved_at: float | None = None
    executed_at: float | None = None
    approval_note: str | None = None


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


class PlanStore:
    """Persist execution plans locally so approvals survive restarts."""

    def __init__(self, store_path: Path):
        self.store_path = store_path
        self.store_path.parent.mkdir(parents=True, exist_ok=True)
        _ensure_file(self.store_path, mode=0o600)

    def load(self) -> Dict[str, ExecutionPlan]:
        try:
            raw_text = self.store_path.read_text(encoding="utf-8").strip()
            if not raw_text:
                return {}
            data = json.loads(raw_text)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

        if data.get("version") != PLAN_STORE_VERSION:
            return {}

        plans: Dict[str, ExecutionPlan] = {}
        for item in data.get("plans", []):
            try:
                item.setdefault(
                    "approval_summary",
                    {
                        "tool": "ssh_execute_plan",
                        "target": item.get("connection_name", ""),
                        "action": item.get("kind", ""),
                        "summary": item.get("summary", ""),
                        "plan_id": item.get("plan_id", ""),
                    },
                )
                plan = ExecutionPlan(**item)
            except TypeError:
                continue
            plans[plan.plan_id] = plan
        return plans

    def save(self, plans: Dict[str, ExecutionPlan]) -> None:
        payload = {
            "version": PLAN_STORE_VERSION,
            "plans": [
                {
                    "plan_id": plan.plan_id,
                    "kind": plan.kind,
                    "connection_name": plan.connection_name,
                    "status": plan.status,
                    "approval_required": plan.approval_required,
                    "risk": plan.risk,
                    "operational_risk": plan.operational_risk,
                    "approval_summary": plan.approval_summary,
                    "summary": plan.summary,
                    "rollback_plan": plan.rollback_plan,
                    "created_at": plan.created_at,
                    "expires_at": plan.expires_at,
                    "payload": plan.payload,
                    "verification": plan.verification,
                    "approved_at": plan.approved_at,
                    "executed_at": plan.executed_at,
                    "approval_note": plan.approval_note,
                }
                for plan in sorted(plans.values(), key=lambda item: item.created_at)
            ],
        }
        _write_secure_text(
            self.store_path,
            json.dumps(payload, indent=2, sort_keys=True),
            mode=0o600,
        )


class AuditLog:
    """Append-only audit log for plan lifecycle events."""

    def __init__(self, log_path: Path):
        self.log_path = log_path
        _ensure_file(self.log_path, mode=0o600)

    def append(self, event: Dict[str, Any]) -> None:
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.log_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, sort_keys=True) + "\n")
        _set_posix_permissions(self.log_path, 0o600)


class SSHMCPServer:
    """MCP Server for SSH operations on remote Ubuntu servers."""

    def __init__(self):
        self.server = Server("ssh-mcp-server")
        self.connections: Dict[str, SSHConnection] = {}
        self.workspace_dir = Path.cwd().resolve(strict=False)
        self.config_path = Path(__file__).resolve().with_name(CONFIG_FILE)
        self.allowed_local_roots = self._load_allowed_local_roots()
        self.credential_store = CredentialStore(Path.home() / CREDENTIAL_STORE_FILE)
        self.plan_store = PlanStore(Path.home() / PLAN_STORE_FILE)
        self.audit_log = AuditLog(self.workspace_dir / AUDIT_LOG_FILE)
        self.plans: Dict[str, ExecutionPlan] = self.plan_store.load()
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

    def _load_server_config(self) -> Dict[str, Any]:
        if not self.config_path.exists():
            return {}

        try:
            raw_text = self.config_path.read_text(encoding="utf-8").strip()
        except OSError as exc:
            logger.warning("Failed to read config file %s: %s", self.config_path, exc)
            return {}

        if not raw_text:
            return {}

        try:
            data = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            logger.warning("Failed to parse config file %s: %s", self.config_path, exc)
            return {}

        if not isinstance(data, dict):
            logger.warning("Config file %s must contain a JSON object", self.config_path)
            return {}

        return data

    def _auto_mode_enabled(self) -> bool:
        config = self._load_server_config()
        raw_mode = str(config.get("auto-mode", AUTO_MODE_DISABLED)).strip().lower()
        if raw_mode not in SUPPORTED_AUTO_MODES:
            logger.warning(
                "Unsupported auto-mode %r in %s. Falling back to %s.",
                raw_mode,
                self.config_path,
                AUTO_MODE_DISABLED,
            )
            return False
        return raw_mode == AUTO_MODE_ENABLED

    def _auto_approve_plan(self, plan: ExecutionPlan, source_task: str) -> None:
        note = f"Auto-approved by {self.config_path.name} for task '{source_task}'."
        plan.status = PLAN_STATUS_APPROVED
        plan.approved_at = time.time()
        plan.approval_note = note
        self._save_plans()
        self._audit_event("plan_approved", plan, extra={"approval_note": note, "auto_approved": True})

    async def _execute_plan_instance(self, plan: ExecutionPlan) -> str:
        connection = self._ensure_connection(plan.connection_name)
        connection.last_used = time.time()

        if plan.kind == PLAN_KIND_COMMAND:
            stdout_text, stderr_text, exit_code = await self._exec_command(
                connection.client,
                plan.payload["command"],
                int(plan.payload.get("timeout", DEFAULT_COMMAND_TIMEOUT)),
            )
            plan.status = PLAN_STATUS_EXECUTED
            plan.executed_at = time.time()
            plan.verification = f"Command exit code {exit_code}"
            self._save_plans()
            self._audit_event("plan_executed", plan, extra={"exit_code": exit_code})
            result = f"Plan '{plan.plan_id}' executed.\nCommand: {plan.payload['command']}\nExit Code: {exit_code}\n"
            if stdout_text:
                result += f"\nSTDOUT:\n{stdout_text}\n"
            if stderr_text:
                result += f"\nSTDERR:\n{stderr_text}\n"
            return result

        if plan.kind == PLAN_KIND_FILE_EDIT:
            remote_path = plan.payload["remote_path"]
            backup_path = f"{remote_path}.ssh-mcp.bak.{int(time.time())}"
            new_bytes = plan.payload["new_content"].encode("utf-8")
            await self._write_remote_file_bytes(
                connection,
                remote_path,
                new_bytes,
                backup_path=backup_path,
            )
            written_bytes = await self._read_remote_file_bytes(connection, remote_path)
            written_hash = hashlib.sha256(written_bytes).hexdigest()
            expected_hash = plan.payload["new_sha256"]
            if written_hash != expected_hash:
                raise RuntimeError(
                    f"Post-write verification failed for {remote_path}: "
                    f"expected {expected_hash}, got {written_hash}"
                )

            plan.status = PLAN_STATUS_EXECUTED
            plan.executed_at = time.time()
            plan.verification = f"Verified SHA256 {written_hash}; backup at {backup_path}"
            self._save_plans()
            self._audit_event(
                "plan_executed",
                plan,
                extra={"sha256": written_hash, "backup_path": backup_path},
            )
            return (
                f"Plan '{plan.plan_id}' executed.\n"
                f"Remote path: {remote_path}\n"
                f"Backup path: {backup_path}\n"
                f"SHA256: {written_hash}"
            )

        if plan.kind == PLAN_KIND_KEY_AUTH:
            credential_name = str(plan.payload["credential_name"])
            key_name = str(plan.payload["key_name"])
            key_comment = str(plan.payload["key_comment"])
            overwrite_saved_credential = bool(
                plan.payload.get("overwrite_saved_credential", False)
            )
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
            plan.status = PLAN_STATUS_EXECUTED
            plan.executed_at = time.time()
            plan.verification = (
                f"Installed key auth and saved credential '{credential_name}'"
            )
            self._save_plans()
            self._audit_event(
                "plan_executed",
                plan,
                extra={"credential_name": credential_name, "key_name": key_name},
            )
            return (
                f"Plan '{plan.plan_id}' executed.\n"
                f"Installed SSH public key on {connection.hostname}\n"
                f"Saved credential: {credential_name}\n"
                f"Key name: {key_name}"
            )

        if plan.kind == PLAN_KIND_UPLOAD:
            source_path = Path(str(plan.payload["local_path"]))
            remote_path = str(plan.payload["remote_path"])

            def upload_file() -> None:
                sftp = connection.client.open_sftp()
                try:
                    sftp.put(str(source_path), remote_path)
                finally:
                    sftp.close()

            await self._run_blocking(upload_file)
            remote_hash = await self._remote_file_sha256(connection, remote_path)
            expected_hash = str(plan.payload["local_sha256"])
            if remote_hash != expected_hash:
                raise RuntimeError(
                    f"Post-upload verification failed for {remote_path}: "
                    f"expected {expected_hash}, got {remote_hash}"
                )

            plan.status = PLAN_STATUS_EXECUTED
            plan.executed_at = time.time()
            plan.verification = f"Verified SHA256 {remote_hash}"
            self._save_plans()
            self._audit_event(
                "plan_executed",
                plan,
                extra={"sha256": remote_hash, "remote_path": remote_path},
            )
            return (
                f"Plan '{plan.plan_id}' executed.\n"
                f"Uploaded: {source_path}\n"
                f"Remote path: {remote_path}\n"
                f"SHA256: {remote_hash}"
            )

        raise RuntimeError(f"Unsupported plan kind: {plan.kind}")

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

    def _ensure_connection(self, connection_name: str) -> SSHConnection:
        if connection_name not in self.connections:
            raise KeyError(f"Connection '{connection_name}' not found")

        connection = self.connections[connection_name]
        if not connection.connected:
            raise RuntimeError(f"Connection '{connection_name}' is not active")

        return connection

    def _new_plan_id(self) -> str:
        digest = hashlib.sha256(f"{time.time_ns()}-{len(self.plans)}".encode("utf-8")).hexdigest()
        return f"plan-{digest[:12]}"

    def _save_plans(self) -> None:
        self.plan_store.save(self.plans)

    def _audit_event(
        self,
        event_type: str,
        plan: ExecutionPlan,
        *,
        extra: Dict[str, Any] | None = None,
    ) -> None:
        event = {
            "ts": time.time(),
            "event": event_type,
            "plan_id": plan.plan_id,
            "kind": plan.kind,
            "connection_name": plan.connection_name,
            "status": plan.status,
            "risk": plan.risk,
            "summary": plan.summary,
        }
        if extra:
            event["extra"] = extra
        self.audit_log.append(event)

    def _is_plan_expired(self, plan: ExecutionPlan) -> bool:
        return time.time() > plan.expires_at

    def _expire_plan_if_needed(self, plan: ExecutionPlan) -> bool:
        if self._is_plan_expired(plan) and plan.status not in (
            PLAN_STATUS_EXECUTED,
            PLAN_STATUS_REJECTED,
        ):
            plan.status = PLAN_STATUS_REJECTED
            if not plan.approval_note:
                plan.approval_note = "Expired before approval/execution."
            self._save_plans()
            self._audit_event("plan_expired", plan)
            return True
        return False

    def _format_plan(self, plan: ExecutionPlan) -> str:
        lines = [
            f"Plan ID: {plan.plan_id}",
            f"Kind: {plan.kind}",
            f"Connection: {plan.connection_name}",
            f"Status: {plan.status}",
            f"Approval required: {'yes' if plan.approval_required else 'no'}",
            f"Risk: {plan.risk}",
            f"Operational risk: {plan.operational_risk}",
            f"Summary: {plan.summary}",
            f"Rollback plan: {plan.rollback_plan}",
            f"Expires at: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(plan.expires_at))}",
        ]
        if plan.approval_note:
            lines.append(f"Approval note: {plan.approval_note}")
        if plan.verification:
            lines.append(f"Verification: {plan.verification}")
        if plan.approval_summary:
            lines.append("Approval summary:")
            for key in ("tool", "target", "action", "summary", "plan_id"):
                value = plan.approval_summary.get(key)
                if value:
                    lines.append(f"- {key}: {value}")
        return "\n".join(lines)

    def _store_plan(
        self,
        *,
        kind: str,
        connection_name: str,
        approval_required: bool,
        risk: str,
        operational_risk: str,
        approval_summary: Dict[str, str],
        summary: str,
        rollback_plan: str,
        payload: Dict[str, Any],
    ) -> ExecutionPlan:
        plan = ExecutionPlan(
            plan_id=self._new_plan_id(),
            kind=kind,
            connection_name=connection_name,
            status=PLAN_STATUS_DRAFT,
            approval_required=approval_required,
            risk=risk,
            operational_risk=operational_risk,
            approval_summary=approval_summary,
            summary=summary,
            rollback_plan=rollback_plan,
            created_at=time.time(),
            expires_at=time.time() + DEFAULT_PLAN_TTL_SECONDS,
            payload=payload,
        )
        if not plan.approval_summary.get("plan_id"):
            plan.approval_summary["plan_id"] = plan.plan_id
        self.plans[plan.plan_id] = plan
        self._save_plans()
        self._audit_event("plan_created", plan)
        return plan

    def _format_plan_summary(self, plan: ExecutionPlan) -> str:
        return (
            f"Plan created: {plan.plan_id}\n"
            f"- tool: {plan.approval_summary.get('tool', 'ssh_execute_plan')}\n"
            f"- target: {plan.approval_summary.get('target', plan.connection_name)}\n"
            f"- action: {plan.approval_summary.get('action', plan.kind)}\n"
            f"- summary: {plan.approval_summary.get('summary', plan.summary)}\n"
            f"- plan id: {plan.plan_id}\n"
            f"Expires at: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(plan.expires_at))}\n"
            f"Next step: call ssh_get_plan for details, then ssh_approve_plan and ssh_execute_plan."
        )

    def _command_contains_shell_meta(self, command: str) -> bool:
        return any(token in command for token in SHELL_META_TOKENS)

    def _classify_command(self, command: str) -> tuple[str, bool, str, str]:
        try:
            tokens = shlex.split(command, posix=True)
        except ValueError:
            return (
                "high",
                True,
                "systemic / partial",
                "Command parsing failed; require manual review before execution.",
            )

        if not tokens:
            return (
                "medium",
                True,
                "local / trivial",
                "Empty command is not executable; provide a concrete command.",
            )

        if self._command_contains_shell_meta(command):
            return (
                "high",
                True,
                "broad / partial",
                "Command uses shell composition or redirection and must be reviewed before execution.",
            )

        executable = tokens[0]
        if executable in SAFE_DIRECT_COMMANDS:
            return (
                "low",
                False,
                "local / trivial",
                "Read-only command matches the direct execution allowlist.",
            )

        if executable in HIGH_RISK_COMMAND_PREFIXES:
            return (
                "high",
                True,
                "contained / partial",
                f"Command starts with '{executable}', which can mutate remote state.",
            )

        return (
            "medium",
            True,
            "contained / partial",
            "Command is not on the direct execution allowlist and requires a reviewed plan.",
        )

    async def _read_remote_file_bytes(
        self, connection: SSHConnection, remote_path: str
    ) -> bytes:
        def read_file() -> bytes:
            sftp = connection.client.open_sftp()
            try:
                with sftp.file(remote_path, "rb") as remote_file:
                    return remote_file.read()
            finally:
                sftp.close()

        return await self._run_blocking(read_file)

    async def _write_remote_file_bytes(
        self,
        connection: SSHConnection,
        remote_path: str,
        content: bytes,
        backup_path: str | None = None,
    ) -> None:
        def write_file() -> None:
            sftp = connection.client.open_sftp()
            try:
                if backup_path is not None:
                    with sftp.file(remote_path, "rb") as source_file:
                        original = source_file.read()
                    with sftp.file(backup_path, "wb") as backup_file:
                        backup_file.write(original)
                with sftp.file(remote_path, "wb") as target_file:
                    target_file.write(content)
            finally:
                sftp.close()

        await self._run_blocking(write_file)

    async def _remote_file_sha256(
        self, connection: SSHConnection, remote_path: str
    ) -> str:
        content = await self._read_remote_file_bytes(connection, remote_path)
        return hashlib.sha256(content).hexdigest()

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
                    name="ssh_read_file",
                    description="Read a remote file over SFTP without modifying it",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "connection_name": {
                                "type": "string",
                                "description": "Name of the SSH connection to use"
                            },
                            "remote_path": {
                                "type": "string",
                                "description": "Remote file path to read"
                            },
                            "encoding": {
                                "type": "string",
                                "description": "Text encoding to use when decoding bytes",
                                "default": "utf-8"
                            }
                        },
                        "required": ["connection_name", "remote_path"]
                    }
                ),
                Tool(
                    name="ssh_plan_command",
                    description="Create a reviewed execution plan for a non-trivial remote command",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "connection_name": {
                                "type": "string",
                                "description": "Name of the SSH connection to use"
                            },
                            "command": {
                                "type": "string",
                                "description": "Remote command to review and plan"
                            },
                            "reason": {
                                "type": "string",
                                "description": "Optional human explanation for why the command is needed"
                            }
                        },
                        "required": ["connection_name", "command"]
                    }
                ),
                Tool(
                    name="ssh_plan_edit",
                    description="Create a managed remote file edit plan that requires approval before writing",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "connection_name": {
                                "type": "string",
                                "description": "Name of the SSH connection to use"
                            },
                            "remote_path": {
                                "type": "string",
                                "description": "Remote file path to modify"
                            },
                            "new_content": {
                                "type": "string",
                                "description": "Full replacement text for the remote file"
                            },
                            "reason": {
                                "type": "string",
                                "description": "Why the file edit is needed"
                            }
                        },
                        "required": ["connection_name", "remote_path", "new_content"]
                    }
                ),
                Tool(
                    name="ssh_list_plans",
                    description="List in-memory command and file edit plans",
                    inputSchema={
                        "type": "object",
                        "properties": {}
                    }
                ),
                Tool(
                    name="ssh_get_plan",
                    description="Show full detail for one stored plan",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "plan_id": {
                                "type": "string",
                                "description": "Stored plan identifier"
                            }
                        },
                        "required": ["plan_id"]
                    }
                ),
                Tool(
                    name="ssh_approve_plan",
                    description="Approve a stored plan so it can be executed",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "plan_id": {
                                "type": "string",
                                "description": "Plan identifier returned by ssh_plan_command or ssh_plan_edit"
                            },
                            "approval_note": {
                                "type": "string",
                                "description": "Optional note captured with the approval"
                            }
                        },
                        "required": ["plan_id"]
                    }
                ),
                Tool(
                    name="ssh_reject_plan",
                    description="Reject a stored plan so it cannot be executed",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "plan_id": {
                                "type": "string",
                                "description": "Plan identifier returned by ssh_plan_command or ssh_plan_edit"
                            },
                            "reason": {
                                "type": "string",
                                "description": "Optional rejection note"
                            }
                        },
                        "required": ["plan_id"]
                    }
                ),
                Tool(
                    name="ssh_execute_plan",
                    description="Execute an approved command or remote file edit plan",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "plan_id": {
                                "type": "string",
                                "description": "Approved plan identifier to execute"
                            }
                        },
                        "required": ["plan_id"]
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
                ),
                Tool(
                    name="ssh_read_audit_log",
                    description="Read the audit log of all plan lifecycle events in a human-readable format",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "limit": {
                                "type": "integer",
                                "description": "Maximum number of recent entries to show (default: 50)",
                                "default": 50
                            },
                            "event_filter": {
                                "type": "string",
                                "description": "Filter by event type: plan_created, plan_approved, plan_rejected, plan_executed, plan_expired"
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
                elif name == "ssh_read_file":
                    return await self._ssh_read_file(arguments)
                elif name == "ssh_plan_command":
                    return await self._ssh_plan_command(arguments)
                elif name == "ssh_plan_edit":
                    return await self._ssh_plan_edit(arguments)
                elif name == "ssh_list_plans":
                    return await self._ssh_list_plans(arguments)
                elif name == "ssh_get_plan":
                    return await self._ssh_get_plan(arguments)
                elif name == "ssh_approve_plan":
                    return await self._ssh_approve_plan(arguments)
                elif name == "ssh_reject_plan":
                    return await self._ssh_reject_plan(arguments)
                elif name == "ssh_execute_plan":
                    return await self._ssh_execute_plan(arguments)
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
                elif name == "ssh_read_audit_log":
                    return await self._ssh_read_audit_log(arguments)
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
        try:
            connection = self._ensure_connection(connection_name)
        except (KeyError, RuntimeError) as e:
            return [TextContent(type="text", text=str(e))]

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

        plan = self._store_plan(
            kind=PLAN_KIND_KEY_AUTH,
            connection_name=connection_name,
            approval_required=not self._auto_mode_enabled(),
            risk="high",
            operational_risk="contained / partial",
            approval_summary={
                "tool": "ssh_execute_plan",
                "target": connection_name,
                "action": "Install SSH public key",
                "summary": f"Save credential {credential_name} on {connection.hostname}",
                "plan_id": "",
            },
            summary=(
                f"Install SSH public key on {connection.hostname} and save credential "
                f"'{credential_name}'"
            ),
            rollback_plan=(
                "Remove the added public key from remote authorized_keys and delete the "
                "saved local credential if rollback is required."
            ),
            payload={
                "credential_name": credential_name,
                "key_name": key_name,
                "key_comment": key_comment,
                "overwrite_saved_credential": overwrite_saved_credential,
            },
        )
        if plan.approval_required:
            message = self._format_plan(plan)
            if plan.payload:
                message += "\nPayload:\n" + json.dumps(plan.payload, indent=2, sort_keys=True)
            return [TextContent(type="text", text=message)]

        self._auto_approve_plan(plan, "ssh_setup_key_auth")
        try:
            result = await self._execute_plan_instance(plan)
            return [TextContent(type="text", text=result)]
        except paramiko.SSHException as e:
            connection.connected = False
            return [TextContent(type="text", text=f"SSH error executing auto-approved plan: {str(e)}")]
        except Exception as e:
            return [TextContent(type="text", text=f"Failed to execute auto-approved plan: {str(e)}")]

    async def _ssh_execute(self, args: Dict[str, Any]) -> List[TextContent]:
        """Execute command on remote server."""
        connection_name = args["connection_name"]
        command = args["command"]
        timeout = args.get("timeout", 30)

        try:
            connection = self._ensure_connection(connection_name)
        except (KeyError, RuntimeError) as e:
            return [TextContent(type="text", text=str(e))]

        risk, approval_required, operational_risk, classification_reason = self._classify_command(
            command
        )
        if approval_required:
            plan = self._store_plan(
                kind=PLAN_KIND_COMMAND,
                connection_name=connection_name,
                approval_required=not self._auto_mode_enabled(),
                risk=risk,
                operational_risk=operational_risk,
                approval_summary={
                    "tool": "ssh_execute_plan",
                    "target": connection_name,
                    "action": "Execute remote command",
                    "summary": command,
                    "plan_id": "",
                },
                summary=f"Review command before execution: {command}",
                rollback_plan="Not executed yet. Approve only after reviewing remote impact.",
                payload={
                    "command": command,
                    "timeout": timeout,
                    "classification_reason": classification_reason,
                },
            )
            if plan.approval_required:
                message = self._format_plan(plan)
                if plan.payload:
                    message += "\nPayload:\n" + json.dumps(plan.payload, indent=2, sort_keys=True)
                return [TextContent(type="text", text=message)]

            self._auto_approve_plan(plan, "ssh_execute")
            try:
                result = await self._execute_plan_instance(plan)
                return [TextContent(type="text", text=result)]
            except paramiko.SSHException as e:
                connection.connected = False
                return [TextContent(type="text", text=f"SSH error executing auto-approved plan: {str(e)}")]
            except Exception as e:
                return [TextContent(type="text", text=f"Failed to execute auto-approved plan: {str(e)}")]

        try:
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
            return [TextContent(type="text", text=f"SSH error: {str(e)}")]
        except Exception as e:
            return [TextContent(type="text", text=f"Execution failed: {str(e)}")]

    async def _ssh_read_file(self, args: Dict[str, Any]) -> List[TextContent]:
        """Read a remote file without modifying it."""
        connection_name = args["connection_name"]
        remote_path = args["remote_path"]
        encoding = args.get("encoding", "utf-8")

        try:
            connection = self._ensure_connection(connection_name)
        except (KeyError, RuntimeError) as e:
            return [TextContent(type="text", text=str(e))]

        try:
            connection.last_used = time.time()
            content = await self._read_remote_file_bytes(connection, remote_path)
            decoded = content.decode(encoding, errors="replace")
            sha256_digest = hashlib.sha256(content).hexdigest()
            result = (
                f"Remote path: {remote_path}\n"
                f"Bytes: {len(content)}\n"
                f"SHA256: {sha256_digest}\n\n"
                f"{decoded}"
            )
            return [TextContent(type="text", text=result)]
        except FileNotFoundError:
            return [TextContent(type="text", text=f"Remote file not found: {remote_path}")]
        except OSError as e:
            return [TextContent(type="text", text=f"Failed to read remote file: {str(e)}")]
        except Exception as e:
            return [TextContent(type="text", text=f"Failed to read remote file: {str(e)}")]

    async def _ssh_plan_command(self, args: Dict[str, Any]) -> List[TextContent]:
        """Create a managed plan for a command that should not run directly."""
        connection_name = args["connection_name"]
        command = args["command"]
        reason = args.get("reason")

        try:
            self._ensure_connection(connection_name)
        except (KeyError, RuntimeError) as e:
            return [TextContent(type="text", text=str(e))]

        risk, approval_required, operational_risk, classification_reason = self._classify_command(
            command
        )
        plan = self._store_plan(
            kind=PLAN_KIND_COMMAND,
            connection_name=connection_name,
            approval_required=approval_required,
            risk=risk,
            operational_risk=operational_risk,
            approval_summary={
                "tool": "ssh_execute_plan",
                "target": connection_name,
                "action": "Execute remote command",
                "summary": command,
                "plan_id": "",
            },
            summary=f"Execute remote command: {command}",
            rollback_plan="Command execution is not inherently reversible; validate command intent before approval.",
            payload={
                "command": command,
                "timeout": args.get("timeout", 30),
                "reason": reason,
                "classification_reason": classification_reason,
            },
        )
        message = self._format_plan(plan)
        if plan.payload:
            message += "\nPayload:\n" + json.dumps(plan.payload, indent=2, sort_keys=True)
        return [TextContent(type="text", text=message)]

    async def _ssh_plan_edit(self, args: Dict[str, Any]) -> List[TextContent]:
        """Create a managed plan for editing a remote file."""
        connection_name = args["connection_name"]
        remote_path = args["remote_path"]
        new_content = args["new_content"]
        reason = args.get("reason")

        try:
            connection = self._ensure_connection(connection_name)
        except (KeyError, RuntimeError) as e:
            return [TextContent(type="text", text=str(e))]

        try:
            original_bytes = await self._read_remote_file_bytes(connection, remote_path)
        except FileNotFoundError:
            return [TextContent(type="text", text=f"Remote file not found: {remote_path}")]
        except Exception as e:
            return [TextContent(type="text", text=f"Failed to inspect remote file: {str(e)}")]

        new_bytes = new_content.encode("utf-8")
        original_hash = hashlib.sha256(original_bytes).hexdigest()
        new_hash = hashlib.sha256(new_bytes).hexdigest()
        plan = self._store_plan(
            kind=PLAN_KIND_FILE_EDIT,
            connection_name=connection_name,
            approval_required=True,
            risk="high",
            operational_risk="contained / partial",
            approval_summary={
                "tool": "ssh_execute_plan",
                "target": connection_name,
                "action": "Replace remote file contents",
                "summary": remote_path,
                "plan_id": "",
            },
            summary=f"Replace remote file contents at {remote_path}",
            rollback_plan=(
                "Server creates a timestamped .bak file before writing. "
                "Restore that backup if rollback is needed."
            ),
            payload={
                "remote_path": remote_path,
                "new_content": new_content,
                "reason": reason,
                "original_sha256": original_hash,
                "new_sha256": new_hash,
                "original_bytes": len(original_bytes),
                "new_bytes": len(new_bytes),
            },
        )
        message = self._format_plan(plan)
        if plan.payload:
            message += "\nPayload:\n" + json.dumps(plan.payload, indent=2, sort_keys=True)
        return [TextContent(type="text", text=message)]

    async def _ssh_list_plans(self, args: Dict[str, Any]) -> List[TextContent]:
        """List all in-memory plans."""
        if not self.plans:
            return [TextContent(type="text", text="No stored plans")]

        lines = ["Stored plans:"]
        for plan in sorted(self.plans.values(), key=lambda item: item.created_at):
            self._expire_plan_if_needed(plan)
            lines.append(
                f"- {plan.plan_id}: {plan.kind} on {plan.connection_name} "
                f"[{plan.status}] risk={plan.risk} approval_required={'yes' if plan.approval_required else 'no'} "
                f"expires={time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(plan.expires_at))}"
            )
        return [TextContent(type="text", text="\n".join(lines))]

    async def _ssh_get_plan(self, args: Dict[str, Any]) -> List[TextContent]:
        """Return full detail for a stored plan."""
        plan_id = args["plan_id"]

        if plan_id not in self.plans:
            return [TextContent(type="text", text=f"Plan '{plan_id}' not found")]

        plan = self.plans[plan_id]
        self._expire_plan_if_needed(plan)
        message = self._format_plan(plan)
        if plan.payload:
            message += "\nPayload:\n" + json.dumps(plan.payload, indent=2, sort_keys=True)
        return [TextContent(type="text", text=message)]

    async def _ssh_approve_plan(self, args: Dict[str, Any]) -> List[TextContent]:
        """Approve a stored plan."""
        plan_id = args["plan_id"]
        approval_note = args.get("approval_note")

        if plan_id not in self.plans:
            return [TextContent(type="text", text=f"Plan '{plan_id}' not found")]

        plan = self.plans[plan_id]
        if self._expire_plan_if_needed(plan):
            return [TextContent(type="text", text=f"Plan '{plan_id}' has expired and must be recreated")]
        if plan.status == PLAN_STATUS_REJECTED:
            return [TextContent(type="text", text=f"Plan '{plan_id}' has been rejected and cannot be approved")]
        if plan.status == PLAN_STATUS_EXECUTED:
            return [TextContent(type="text", text=f"Plan '{plan_id}' has already been executed")]

        plan.status = PLAN_STATUS_APPROVED
        plan.approved_at = time.time()
        plan.approval_note = approval_note
        self._save_plans()
        self._audit_event("plan_approved", plan, extra={"approval_note": approval_note})
        return [TextContent(type="text", text=f"Approved plan '{plan_id}'.\n{self._format_plan(plan)}")]

    async def _ssh_reject_plan(self, args: Dict[str, Any]) -> List[TextContent]:
        """Reject a stored plan."""
        plan_id = args["plan_id"]
        reason = args.get("reason")

        if plan_id not in self.plans:
            return [TextContent(type="text", text=f"Plan '{plan_id}' not found")]

        plan = self.plans[plan_id]
        if plan.status == PLAN_STATUS_EXECUTED:
            return [TextContent(type="text", text=f"Plan '{plan_id}' has already been executed")]

        plan.status = PLAN_STATUS_REJECTED
        plan.approval_note = reason
        self._save_plans()
        self._audit_event("plan_rejected", plan, extra={"reason": reason})
        return [TextContent(type="text", text=f"Rejected plan '{plan_id}'.\n{self._format_plan(plan)}")]

    async def _ssh_execute_plan(self, args: Dict[str, Any]) -> List[TextContent]:
        """Execute an approved command or remote file edit plan."""
        plan_id = args["plan_id"]

        if plan_id not in self.plans:
            return [TextContent(type="text", text=f"Plan '{plan_id}' not found")]

        plan = self.plans[plan_id]
        if self._expire_plan_if_needed(plan):
            return [TextContent(type="text", text=f"Plan '{plan_id}' has expired and must be recreated")]
        if plan.status != PLAN_STATUS_APPROVED:
            return [TextContent(
                type="text",
                text=f"Plan '{plan_id}' is not approved. Current status: {plan.status}",
            )]

        try:
            result = await self._execute_plan_instance(plan)
            return [TextContent(type="text", text=result)]
        except paramiko.SSHException as e:
            try:
                connection = self._ensure_connection(plan.connection_name)
                connection.connected = False
            except (KeyError, RuntimeError):
                pass
            return [TextContent(type="text", text=f"SSH error executing plan: {str(e)}")]
        except Exception as e:
            return [TextContent(type="text", text=f"Failed to execute plan: {str(e)}")]

    async def _ssh_upload_file(self, args: Dict[str, Any]) -> List[TextContent]:
        """Upload file to remote server via SFTP."""
        connection_name = args["connection_name"]
        local_path = args["local_path"]
        remote_path = args["remote_path"]

        try:
            connection = self._ensure_connection(connection_name)
        except (KeyError, RuntimeError) as e:
            return [TextContent(type="text", text=str(e))]

        try:
            source_path = self._validate_local_path(local_path, require_exists=True)
        except FileNotFoundError:
            return [TextContent(type="text", text=f"Local file not found: {local_path}")]
        except ValueError as e:
            return [TextContent(type="text", text=str(e))]

        try:
            local_bytes = source_path.read_bytes()
        except Exception as e:
            return [TextContent(type="text", text=f"Failed to read local file for upload: {str(e)}")]

        plan = self._store_plan(
            kind=PLAN_KIND_UPLOAD,
            connection_name=connection_name,
            approval_required=not self._auto_mode_enabled(),
            risk="high",
            operational_risk="contained / partial",
            approval_summary={
                "tool": "ssh_execute_plan",
                "target": connection_name,
                "action": "Upload local file",
                "summary": f"{source_path.name} -> {remote_path}",
                "plan_id": "",
            },
            summary=f"Upload local file {source_path.name} to {remote_path}",
            rollback_plan=(
                "Remove or replace the uploaded remote file manually if rollback is required."
            ),
            payload={
                "local_path": str(source_path),
                "remote_path": remote_path,
                "local_sha256": hashlib.sha256(local_bytes).hexdigest(),
                "local_bytes": len(local_bytes),
            },
        )
        if plan.approval_required:
            message = self._format_plan(plan)
            if plan.payload:
                message += "\nPayload:\n" + json.dumps(plan.payload, indent=2, sort_keys=True)
            return [TextContent(type="text", text=message)]

        self._auto_approve_plan(plan, "ssh_upload_file")
        try:
            result = await self._execute_plan_instance(plan)
            return [TextContent(type="text", text=result)]
        except paramiko.SSHException as e:
            connection.connected = False
            return [TextContent(type="text", text=f"SSH error executing auto-approved plan: {str(e)}")]
        except Exception as e:
            return [TextContent(type="text", text=f"Failed to execute auto-approved plan: {str(e)}")]

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

    async def _ssh_read_audit_log(self, args: Dict[str, Any]) -> List[TextContent]:
        """Read and format audit log entries in human-readable form."""
        limit = int(args.get("limit", 50))
        event_filter = args.get("event_filter", "").strip().lower()

        EVENT_LABELS = {
            "plan_created": "CREATED",
            "plan_approved": "APPROVED",
            "plan_rejected": "REJECTED",
            "plan_executed": "EXECUTED",
            "plan_expired": "EXPIRED",
        }

        try:
            raw = self.audit_log.log_path.read_text(encoding="utf-8").strip()
        except FileNotFoundError:
            return [TextContent(type="text", text="Audit log does not exist.")]

        if not raw:
            return [TextContent(type="text", text="Audit log is empty. No events recorded yet.")]

        entries = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue

        if event_filter:
            entries = [e for e in entries if e.get("event", "").lower() == event_filter]

        entries = entries[-limit:]

        if not entries:
            filter_note = f" for event '{event_filter}'" if event_filter else ""
            return [TextContent(type="text", text=f"No records found{filter_note}.")]

        lines = [f"Audit Log ({len(entries)} entries)\n{'=' * 48}"]
        for entry in entries:
            ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(entry.get("ts", 0)))
            event = entry.get("event", "unknown")
            label = EVENT_LABELS.get(event, event.upper())
            plan_id = entry.get("plan_id", "-")
            kind = entry.get("kind", "-")
            conn = entry.get("connection_name", "-")
            risk = entry.get("risk", "-")
            summary = entry.get("summary", "-")

            lines.append(
                f"\n[{ts}] {label}"
                f"\n  Plan       : {plan_id}"
                f"\n  Kind       : {kind}"
                f"\n  Connection : {conn}"
                f"\n  Risk       : {risk}"
                f"\n  Summary    : {summary}"
            )

            extra = entry.get("extra")
            if extra:
                for k, v in extra.items():
                    lines.append(f"  {k:10}: {v}")

        return [TextContent(type="text", text="\n".join(lines))]

    async def run(self):
        """Run the MCP server."""
        async with stdio_server() as (read_stream, write_stream):
            await self.server.run(
                read_stream,
                write_stream,
                InitializationOptions(
                    server_name="ssh-mcp-server",
                    server_version="1.1.0",
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
