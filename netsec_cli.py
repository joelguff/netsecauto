#!/usr/bin/env python3
# Network Security CLI Tool
import os
import sys
import json
import argparse
import getpass
import logging
from utils.device_connector import DeviceConnector
from utils.security_checks import SecurityChecker
from utils.config_parser import ConfigParser

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def load_devices(config_file):
    """Load device information from JSON config file"""
    try:
        with open(config_file, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logger.error(f"Error loading device configuration: {e}")
        sys.exit(1)

def main():
    # Create argument parser
    parser = argparse.ArgumentParser(description='Network Security Automation Tool')
    
    parser.add_argument('--config', default='devices.json', 
                        help='Path to device configuration file (default: devices.json)')
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Command: Connect to device
    connect_parser = subparsers.add_parser('connect', help='Connect to and run commands on a device')
    connect_parser.add_argument('device', help='Device name or IP address')
    connect_parser.add_argument('--type', default='cisco_ios', 
                               help='Device type (default: cisco_ios)')
    connect_parser.add_argument('--commands', nargs='+', 
                               help='Commands to run on the device')
    connect_parser.add_argument('--username', help='Username for device login')
    
    # Command: List devices
    list_parser = subparsers.add_parser('list', help='List all configured devices')
    
    # Command: Security check
    check_parser = subparsers.add_parser('check', help='Run security checks on devices')
    check_parser.add_argument('--device', help='Device name or IP (all devices if not specified)')
    check_parser.add_argument('--check-type', choices=['all', 'password', 'access', 'services'],
                             default='all', help='Type of security check to run')
    
    # Command: Backup configuration
    backup_parser = subparsers.add_parser('backup', help='Backup device configurations')
    backup_parser.add_argument('--device', help='Device name or IP (all devices if not specified)')
    backup_parser.add_argument('--output-dir', default='./backups', 
                              help='Directory to store backups')
    
    args = parser.parse_args()
    
    # Load device configuration
    if os.path.exists(args.config):
        devices = load_devices(args.config)
    else:
        if args.command != 'connect' or not args.device:
            logger.error(f"Configuration file {args.config} not found")
            sys.exit(1)
        devices = {}

    # Execute the specified command
    if args.command == 'list':
        print("\nConfigured Devices:")
        print("=" * 50)
        for name, details in devices.items():
            print(f"Name: {name}")
            print(f"IP: {details.get('ip', 'N/A')}")
            print(f"Type: {details.get('device_type', 'N/A')}")
            print("-" * 50)
    
    elif args.command == 'connect':
        device_name = args.device
        device_info = {}
        
        # Get device info from config or command line
        if device_name in devices:
            device_info = devices[device_name]
        else:
            device_info['ip'] = device_name
            device_info['device_type'] = args.type
        
        # Get username and password
        username = args.username or device_info.get('username') or input("Username: ")
        password = device_info.get('password') or getpass.getpass("Password: ")
        
        # Connect to the device
        connector = DeviceConnector(
            ip=device_info['ip'],
            device_type=device_info.get('device_type', 'cisco_ios'),
            username=username,
            password=password
        )
        
        try:
            connector.connect()
            if args.commands:
                for cmd in args.commands:
                    print(f"\nExecuting: {cmd}")
                    output = connector.execute_command(cmd)
                    print(output)
            else:
                print(f"Connected to {device_name} ({device_info['ip']})")
                # Interactive mode
                while True:
                    cmd = input("\nEnter command (or 'exit' to quit): ")
                    if cmd.lower() in ('exit', 'quit'):
                        break
                    output = connector.execute_command(cmd)
                    print(output)
            
            connector.disconnect()
        except Exception as e:
            logger.error(f"Error connecting to device: {e}")
            
    elif args.command == 'check':
        checker = SecurityChecker()
        device_list = []
        
        if args.device:
            if args.device in devices:
                device_list = [args.device]
            else:
                logger.error(f"Device {args.device} not found in configuration")
                sys.exit(1)
        else:
            device_list = list(devices.keys())
        
        for device_name in device_list:
            device_info = devices[device_name]
            # Get password if not in config
            if 'password' not in device_info:
                device_info['password'] = getpass.getpass(f"Password for {device_name}: ")
            
            connector = DeviceConnector(
                ip=device_info['ip'],
                device_type=device_info.get('device_type', 'cisco_ios'),
                username=device_info.get('username', ''),
                password=device_info['password']
            )
            
            try:
                connector.connect()
                print(f"\nRunning security checks on {device_name}...")
                
                if args.check_type in ('all', 'password'):
                    checker.check_password_policy(connector)
                
                if args.check_type in ('all', 'access'):
                    checker.check_access_controls(connector)
                
                if args.check_type in ('all', 'services'):
                    checker.check_unnecessary_services(connector)
                
                connector.disconnect()
            except Exception as e:
                logger.error(f"Error checking device {device_name}: {e}")
    
    elif args.command == 'backup':
        # Ensure backup directory exists
        os.makedirs(args.output_dir, exist_ok=True)
        
        device_list = []
        if args.device:
            if args.device in devices:
                device_list = [args.device]
            else:
                logger.error(f"Device {args.device} not found in configuration")
                sys.exit(1)
        else:
            device_list = list(devices.keys())
        
        for device_name in device_list:
            device_info = devices[device_name]
            # Get password if not in config
            if 'password' not in device_info:
                device_info['password'] = getpass.getpass(f"Password for {device_name}: ")
            
            connector = DeviceConnector(
                ip=device_info['ip'],
                device_type=device_info.get('device_type', 'cisco_ios'),
                username=device_info.get('username', ''),
                password=device_info['password']
            )
            
            try:
                connector.connect()
                print(f"Backing up configuration for {device_name}...")
                
                # Get running config
                config = connector.get_config()
                
                # Save to file
                filename = f"{args.output_dir}/{device_name}_{connector.get_current_timestamp()}.cfg"
                with open(filename, 'w') as f:
                    f.write(config)
                
                print(f"Configuration saved to {filename}")
                connector.disconnect()
            except Exception as e:
                logger.error(f"Error backing up device {device_name}: {e}")
    
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
