# Network Security Automation Tool

A comprehensive network security automation platform designed for network engineers and security professionals. This tool provides SSH-driven security management, device configuration monitoring, and intelligent network insights.

## Features

- **Device Management**: Add, edit, and manage network devices
- **Security Auditing**: Automated security checks and compliance verification
- **Configuration Backup**: Track and compare device configurations
- **Real-Time Monitoring**: Monitor device status and performance metrics
- **Network Topology**: Interactive visualization of your network infrastructure
- **AI-Powered Configuration**: Get intelligent suggestions for secure configurations

## Setup and Installation

### Quick Start (Demo Environment)

For a quick demonstration with sample data:

```bash
./start_demo.sh
```

This single-click script will:
1. Stop any running processes
2. Reset the database with fresh sample data
3. Display all demo information
4. Start the web application

You can log in with:

- **Username**: demo
- **Password**: demo123

### Running on Your System

To run the application:

1. Make sure all script files are executable:
   ```bash
   chmod +x *.sh
   ```

2. Use the start_demo.sh script:
   ```bash
   ./start_demo.sh
   ```

3. The application will be available on http://localhost:8080

### Manual Setup

For a manual setup with a clean database:

```bash
# Install dependencies
pip install -r project-requirements.txt

# Start the server
python main.py
```

## Production Deployment

For production environments, use the production script which uses Gunicorn:

```bash
./run_production.sh
```

## System Requirements

- Python 3.9+
- Flask 2.2.5 and Werkzeug 2.2.3
- SQLite (for demo) or PostgreSQL (for production)
- Netmiko 3.3.3 and TextFSM 1.1.2 for device connectivity

## Troubleshooting

- **Port Conflicts**: If port 8080 is in use, modify the port in workflow_start.sh and main.py
- **Database Issues**: Run `./reset_and_fix_errors.sh` to completely rebuild the database
- **Password Errors**: If you see "unsupported hash type" errors, run `python rebuild_database.py`
- **Flask Version Problems**: Check versions with `python -m flask --version` (should be Flask 2.2.5 and Werkzeug 2.2.3)
- **Connectivity Problems**: Ensure network devices are reachable and credentials are correct

## Author

Joel Aaron Guff

[LinkedIn](https://www.linkedin.com/in/joelgff/)