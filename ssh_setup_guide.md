# SSH Setup Guide for MCP Server

## 🔐 Setting up SSH Key Authentication (Recommended)

### 1. Generate SSH Key Pair (if you don't have one)
```bash
# On your local machine
ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa_ubuntu
```

### 2. Copy Public Key to Ubuntu Server
```bash
# Method 1: Using ssh-copy-id
ssh-copy-id -i ~/.ssh/id_rsa_ubuntu.pub username@server_ip

# Method 2: Manual copy
cat ~/.ssh/id_rsa_ubuntu.pub | ssh username@server_ip "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys"
```

### 3. Test SSH Connection
```bash
ssh -i ~/.ssh/id_rsa_ubuntu username@server_ip
```

### 4. Use in Claude MCP
Ask Claude: "Connect to my server 192.168.1.100 using SSH key ~/.ssh/id_rsa_ubuntu with username ubuntu"

## 🔑 Connection Examples

### Password Authentication
- **Server IP**: 192.168.1.100
- **Username**: ubuntu
- **Password**: mypassword123
- **Port**: 22 (default)

Tell Claude: "Connect to Ubuntu server 192.168.1.100 with username ubuntu and password mypassword123"

### SSH Key Authentication
- **Server IP**: 10.0.0.50
- **Username**: admin
- **Key Path**: ~/.ssh/id_rsa
- **Port**: 2222 (custom)

Tell Claude: "Connect to server 10.0.0.50 port 2222 using SSH key ~/.ssh/id_rsa with username admin"

### Multiple Connections
- **Server 1**: "Connect to production server 10.0.1.100 with key ~/.ssh/prod_key as user deploy, name this connection 'prod'"
- **Server 2**: "Connect to staging server 10.0.1.200 with password stagingpass123 as user ubuntu, name this connection 'staging'"

## 🛡️ Security Notes

1. **Never hardcode passwords** in configuration files
2. **Use SSH keys** whenever possible
3. **Use strong passwords** if keys aren't available
4. **Limit SSH access** using firewall rules
5. **Change default SSH port** (22) if needed
6. **Disable root login** and use sudo instead

## 🔧 Common Commands After Connection

Once connected, you can ask Claude to:

- **Run commands**: "Execute 'df -h' on the prod server"
- **Upload files**: "Upload local file /path/to/file.txt to /home/ubuntu/ on staging server"
- **Download files**: "Download /var/log/app.log from prod server to ./logs/"
- **Check health**: "Check health of all SSH connections"
- **List connections**: "Show me all active SSH connections"