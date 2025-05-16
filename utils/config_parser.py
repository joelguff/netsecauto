# Configuration parsing utilities
import re
import logging
import os
from datetime import datetime
try:
    import textfsm
    from textfsm import TextFSM
    TEXTFSM_AVAILABLE = True
except ImportError:
    TEXTFSM_AVAILABLE = False
    logging.warning("TextFSM not available. Advanced parsing will be disabled.")

logger = logging.getLogger(__name__)

class ConfigParser:
    """Class to parse network device configurations"""
    
    def __init__(self, template_dir=None):
        """Initialize the configuration parser
        
        Args:
            template_dir (str, optional): Directory containing TextFSM templates.
        """
        self.template_dir = template_dir
    
    def parse_with_textfsm(self, command_output, template_file):
        """Parse command output using TextFSM templates
        
        Args:
            command_output (str): Output from device command
            template_file (str): Path to TextFSM template file
            
        Returns:
            list: Parsed data as list of dictionaries
        """
        if not TEXTFSM_AVAILABLE:
            logger.error("TextFSM library not available")
            return None
            
        try:
            with open(template_file, 'r') as template:
                fsm = TextFSM(template)
                result = fsm.ParseText(command_output)
                
                # Convert to list of dictionaries for easier handling
                parsed_data = []
                for item in result:
                    parsed_data.append(dict(zip(fsm.header, item)))
                
                return parsed_data
                
        except Exception as e:
            logger.error(f"Error parsing with TextFSM: {str(e)}")
            return None
    
    def parse_interfaces(self, config):
        """Parse interface configurations from device config
        
        Args:
            config (str): Device configuration
            
        Returns:
            dict: Dictionary of interfaces and their configurations
        """
        interfaces = {}
        
        # Match interface sections in the config
        interface_pattern = r'interface ([^\n]+)(?:\n\s+([^\!]+))?'
        interface_matches = re.finditer(interface_pattern, config, re.DOTALL)
        
        for match in interface_matches:
            interface_name = match.group(1).strip()
            interface_config = match.group(2).strip() if match.group(2) else ""
            
            interfaces[interface_name] = {
                'config': interface_config,
                'shutdown': 'shutdown' in interface_config,
                'ip': self._extract_ip_address(interface_config),
                'acl_in': self._extract_acl(interface_config, 'in'),
                'acl_out': self._extract_acl(interface_config, 'out')
            }
        
        return interfaces
    
    def parse_acls(self, config):
        """Parse ACL configurations from device config
        
        Args:
            config (str): Device configuration
            
        Returns:
            dict: Dictionary of ACLs and their rules
        """
        acls = {}
        
        # Match standard ACLs
        std_acl_pattern = r'access-list (\d+) (permit|deny) (.+)'
        std_acl_matches = re.finditer(std_acl_pattern, config)
        
        for match in std_acl_matches:
            acl_id = match.group(1)
            action = match.group(2)
            target = match.group(3).strip()
            
            if acl_id not in acls:
                acls[acl_id] = []
                
            acls[acl_id].append({
                'action': action,
                'target': target,
                'type': 'standard'
            })
        
        # Match named/extended ACLs
        ext_acl_pattern = r'ip access-list (standard|extended) (.+?)(?:\n\s+(.+?))?(?=\nip access-list|\n\w|\Z)'
        ext_acl_matches = re.finditer(ext_acl_pattern, config, re.DOTALL)
        
        for match in ext_acl_matches:
            acl_type = match.group(1)
            acl_name = match.group(2).strip()
            acl_body = match.group(3).strip() if match.group(3) else ""
            
            if acl_name not in acls:
                acls[acl_name] = []
                
            # Parse individual rules
            for line in acl_body.split('\n'):
                line = line.strip()
                if not line or line.startswith('remark'):
                    continue
                    
                parts = line.split()
                if len(parts) >= 2:
                    action = parts[0]
                    target = ' '.join(parts[1:])
                    
                    acls[acl_name].append({
                        'action': action,
                        'target': target,
                        'type': acl_type
                    })
        
        return acls
    
    def parse_users(self, config):
        """Parse user accounts from device config
        
        Args:
            config (str): Device configuration
            
        Returns:
            list: List of user accounts
        """
        users = []
        
        # Match user configurations
        user_pattern = r'username (.+?) privilege (\d+) (.+)'
        user_matches = re.finditer(user_pattern, config)
        
        for match in user_matches:
            username = match.group(1).strip()
            privilege = match.group(2)
            config = match.group(3).strip()
            
            # Determine password type
            password_type = 'unknown'
            if 'password' in config:
                if 'secret' in config:
                    password_type = 'secret'
                else:
                    password_type = 'password'
            
            users.append({
                'username': username,
                'privilege': privilege,
                'password_type': password_type
            })
        
        return users
    
    def compare_configs(self, old_config, new_config):
        """Compare two configurations and identify differences
        
        Args:
            old_config (str): Previous configuration
            new_config (str): Current configuration
            
        Returns:
            dict: Dictionary with added, removed, and modified lines
        """
        # Split configs into lines and remove empty lines
        old_lines = [line.strip() for line in old_config.splitlines() if line.strip()]
        new_lines = [line.strip() for line in new_config.splitlines() if line.strip()]
        
        # Find added and removed lines
        added = [line for line in new_lines if line not in old_lines]
        removed = [line for line in old_lines if line not in new_lines]
        
        return {
            'added': added,
            'removed': removed,
            'added_count': len(added),
            'removed_count': len(removed)
        }
    
    def generate_config_diff_report(self, device_name, old_config, new_config, output_dir='./reports'):
        """Generate a configuration difference report
        
        Args:
            device_name (str): Name of the device
            old_config (str): Previous configuration
            new_config (str): Current configuration
            output_dir (str, optional): Directory to save the report. Defaults to './reports'.
            
        Returns:
            str: Path to the generated report
        """
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)
        
        # Get diff
        diff = self.compare_configs(old_config, new_config)
        
        # Generate report filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{output_dir}/{device_name}_diff_{timestamp}.txt"
        
        # Write report
        with open(filename, 'w') as f:
            f.write(f"Configuration Difference Report for {device_name}\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 50 + "\n\n")
            
            f.write(f"Summary: {diff['added_count']} additions, {diff['removed_count']} removals\n\n")
            
            if diff['added']:
                f.write("ADDED CONFIGURATION LINES:\n")
                f.write("-" * 30 + "\n")
                for line in diff['added']:
                    f.write(f"+ {line}\n")
                f.write("\n")
            
            if diff['removed']:
                f.write("REMOVED CONFIGURATION LINES:\n")
                f.write("-" * 30 + "\n")
                for line in diff['removed']:
                    f.write(f"- {line}\n")
                f.write("\n")
        
        logger.info(f"Configuration diff report saved to {filename}")
        return filename
    
    def _extract_ip_address(self, interface_config):
        """Extract IP address from interface configuration
        
        Args:
            interface_config (str): Interface configuration section
            
        Returns:
            str: IP address/mask or None if not found
        """
        ip_match = re.search(r'ip address ([\d\.]+) ([\d\.]+)', interface_config)
        if ip_match:
            return f"{ip_match.group(1)}/{ip_match.group(2)}"
        return None
    
    def _extract_acl(self, interface_config, direction):
        """Extract applied ACL from interface configuration
        
        Args:
            interface_config (str): Interface configuration section
            direction (str): 'in' or 'out'
            
        Returns:
            str: ACL name/number or None if not found
        """
        acl_match = re.search(r'ip access-group (\S+) (?:' + direction + ')', interface_config)
        if acl_match:
            return acl_match.group(1)
        return None
