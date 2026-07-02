## Task: Configurable auto-mode for plan bypass
Mode: Standard
Risk: Medium
Confidence: Stable
Operational risk: Contained / Trivial
Rollback plan: Revert `ssh_mcp_server.py`, `README.md`, and `config.json` to restore plan-only behavior.
Change budget: [files 4] [functions: __init__, config loader helpers, _ssh_execute, _ssh_setup_key_auth, _ssh_upload_file, _ssh_execute_plan] [interfaces: config.json schema] [state mutations: local executed-plan persistence]

### Scope
- `ssh_mcp_server.py` — add `config.json` support and global `auto-mode` behavior
- `README.md` — document the new config schema and behavior
- `config.json` — provide default config example
- `tasks/todo.md` — track plan and review

### Steps
- [x] Inspect current plan decision flow and adjacent patterns
- [x] Add config loader and auto-mode helper
- [x] Wire `auto-mode` into applicable task handlers
- [x] Document config usage and defaults
- [x] Verify behavior locally and review diff

### Review
- Completed: Added `config.json` support with `auto-mode` values `enabled` and `disabled`; `ssh_execute`, `ssh_upload_file`, and `ssh_setup_key_auth` now auto-approve and run when enabled.
- Out-of-scope flagged: None.
- Assumptions invalidated: Initial per-task config assumption was replaced with a simpler global `auto-mode` after user clarification.
- Known debt (acknowledged): None.
- Limitations: Explicit plan tools such as `ssh_plan_command` and `ssh_plan_edit` remain manual by design; local verification covered `ssh_execute` and `ssh_upload_file` paths, not a live SSH run for `ssh_setup_key_auth`.
