#!/usr/bin/env python3
"""
SSH Connection Examples for Claude MCP Server
"""

# Example connection configurations
EXAMPLE_CONNECTIONS = {
    "production": {
        "hostname": "10.0.1.100",
        "username": "deploy",
        "private_key_path": "~/.ssh/prod_key",
        "port": 22,
        "connection_name": "prod"
    },

    "staging": {
        "hostname": "10.0.1.200",
        "username": "ubuntu",
        "password": "staging_password_123",
        "port": 22,
        "connection_name": "staging"
    },

    "development": {
        "hostname": "192.168.1.100",
        "username": "developer",
        "private_key_path": "~/.ssh/id_rsa",
        "port": 2222,
        "connection_name": "dev"
    },

    "local_vm": {
        "hostname": "127.0.0.1",
        "username": "ubuntu",
        "password": "ubuntu",
        "port": 22,
        "connection_name": "local"
    }
}

def print_connection_examples():
    """Print example connection commands for Claude."""
    print("SSH Connection Examples for Claude MCP:")
    print("=" * 50)

    for name, config in EXAMPLE_CONNECTIONS.items():
        print(f"\n{name.upper()} Server:")
        if "password" in config:
            claude_command = f"Connect to {config['hostname']} with username {config['username']} and password {config['password']}"
        else:
            claude_command = f"Connect to {config['hostname']} using SSH key {config['private_key_path']} with username {config['username']}"

        if config['port'] != 22:
            claude_command += f" on port {config['port']}"

        claude_command += f", name this connection '{config['connection_name']}'"

        print(f"Claude command: \"{claude_command}\"")
        print(f"Raw config: {config}")

if __name__ == "__main__":
    print_connection_examples()