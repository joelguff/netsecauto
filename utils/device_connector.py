# Device connection handling
import time
import logging
from datetime import datetime
from utils.telnetlib_compat import *  # Import our compatibility layer
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException

logger = logging.getLogger(__name__)

class DeviceConnector:
    """Class to handle connections to network devices using Netmiko"""
    
    def __init__(self, ip, device_type, username, password, port=22, secret=None):
        """Initialize device connection parameters
        
        Args:
            ip (str): IP address of the device
            device_type (str): Device type as defined by Netmiko (e.g. cisco_ios)
            username (str): Username for authentication
            password (str): Password for authentication
            port (int, optional): SSH port. Defaults to 22.
            secret (str, optional): Enable secret for privileged mode. Defaults to None.
        """
        self.ip = ip
        self.device_type = device_type
        self.username = username
        self.password = password
        self.port = port
        self.secret = secret
        self.connection = None
        self.device_info = {}
    
    def connect(self):
        """Establish connection to the device"""
        logger.debug(f"Connecting to {self.ip} ({self.device_type})")
        
        device_params = {
            'device_type': self.device_type,
            'host': self.ip,
            'username': self.username,
            'password': self.password,
            'port': self.port,
            'session_log': 'session.log'
        }
        
        if self.secret:
            device_params['secret'] = self.secret
        
        try:
            self.connection = ConnectHandler(**device_params)
            if self.secret:
                self.connection.enable()
            
            # Get basic device information
            self.device_info['hostname'] = self.get_hostname()
            logger.info(f"Connected to {self.device_info.get('hostname', self.ip)}")
            return True
            
        except NetmikoTimeoutException:
            logger.error(f"Connection timeout when connecting to {self.ip}")
            raise
        except NetmikoAuthenticationException:
            logger.error(f"Authentication failed for {self.ip}")
            raise
        except Exception as e:
            logger.error(f"Error connecting to {self.ip}: {str(e)}")
            raise
    
    def disconnect(self):
        """Close the connection to the device"""
        if self.connection:
            self.connection.disconnect()
            logger.debug(f"Disconnected from {self.ip}")
    
    def execute_command(self, command):
        """Execute a command on the device
        
        Args:
            command (str): Command to execute
            
        Returns:
            str: Command output
        """
        if not self.connection:
            raise ConnectionError("Not connected to device")
        
        logger.debug(f"Executing command: {command}")
        try:
            output = self.connection.send_command(command)
            return output
        except Exception as e:
            logger.error(f"Error executing command: {str(e)}")
            raise
    
    def execute_commands(self, commands):
        """Execute multiple commands on the device
        
        Args:
            commands (list): List of commands to execute
            
        Returns:
            dict: Dictionary with commands as keys and outputs as values
        """
        results = {}
        for cmd in commands:
            results[cmd] = self.execute_command(cmd)
        return results
    
    def get_config(self):
        """Get the running configuration of the device
        
        Returns:
            str: Device configuration
        """
        if self.device_type.startswith('cisco'):
            return self.execute_command('show running-config')
        elif self.device_type.startswith('juniper'):
            return self.execute_command('show configuration')
        else:
            logger.warning(f"Unknown device type for config retrieval: {self.device_type}")
            return self.execute_command('show running-config')
    
    def get_hostname(self):
        """Get the hostname of the device
        
        Returns:
            str: Device hostname
        """
        try:
            if self.device_type.startswith('cisco'):
                output = self.execute_command('show running-config | include hostname')
                return output.split('hostname ')[1].strip() if 'hostname ' in output else self.ip
            elif self.device_type.startswith('juniper'):
                output = self.execute_command('show configuration system host-name')
                return output.split('host-name ')[1].strip().rstrip(';') if 'host-name ' in output else self.ip
            else:
                logger.warning(f"Unknown device type for hostname retrieval: {self.device_type}")
                return self.ip
        except Exception as e:
            logger.error(f"Error getting hostname: {str(e)}")
            return self.ip
    
    def configure(self, commands):
        """Configure the device with the given commands
        
        Args:
            commands (list): List of configuration commands
            
        Returns:
            str: Configuration output
        """
        if not self.connection:
            raise ConnectionError("Not connected to device")
        
        logger.debug(f"Configuring device with {len(commands)} commands")
        try:
            output = self.connection.send_config_set(commands)
            return output
        except Exception as e:
            logger.error(f"Error configuring device: {str(e)}")
            raise
    
    def get_current_timestamp(self):
        """Get current timestamp in a filename-friendly format
        
        Returns:
            str: Current timestamp
        """
        return datetime.now().strftime("%Y%m%d_%H%M%S")
