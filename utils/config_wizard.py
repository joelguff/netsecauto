"""
AI-Powered Configuration Wizard Module

This module provides an intelligent wizard interface for generating network device configurations
with AI-assisted guidance and customized templates using machine learning techniques.

It includes:
- ML-based configuration analysis and recommendations
- Template-based configuration generation
- Best practice suggestions using predictive models
- Security-focused configuration scoring and assessment
- Friendly guidance through the configuration process
"""

import json
import logging
import os
import re
import numpy as np
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import KMeans
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

logger = logging.getLogger(__name__)

class ConfigWizard:
    """AI-Powered Configuration Wizard for generating device configurations with ML-based guidance"""
    
    def __init__(self):
        """Initialize the configuration wizard with machine learning models"""
        self.templates_dir = os.path.join(os.path.dirname(__file__), '../templates/config_templates')
        self.device_templates = self._load_templates()
        self.security_recommendations = self._load_security_recommendations()
        
        # ML model parameters
        self.vectorizer = TfidfVectorizer(max_features=100, stop_words='english')
        self.kmeans = None  # Will be initialized when needed
        self.rf_classifier = None  # Will be initialized when needed
        self.scaler = StandardScaler()
        
        # Load or initialize ML models
        self._initialize_ml_models()
        
        # Sample configurations for training/analysis
        self.sample_configs = self._load_sample_configs()
        
        # Feature extraction patterns
        self.feature_patterns = {
            'password_encryption': r'service\s+password-encryption',
            'ssh_version': r'ip\s+ssh\s+version\s+2|ssh\s+version\s+2|protocol-version\s+v2',
            'access_list': r'access-list|ip\s+access-list|firewall\s+filter',
            'timeout': r'exec-timeout|session-timeout|timeout',
            'banner': r'banner\s+login|banner\s+motd|login\s+message',
            'logging': r'logging|syslog',
            'ntp': r'ntp\s+server',
            'tacacs': r'tacacs|aaa',
            'snmp': r'snmp',
            'https': r'http\s+secure|https'
        }
        
    def _load_templates(self) -> Dict[str, Dict[str, Any]]:
        """Load device templates from JSON files
        
        Returns:
            Dict: Dictionary of device templates by device type
        """
        templates = {}
        templates_file = os.path.join(os.path.dirname(__file__), 'data/config_templates.json')
        
        # Create templates directory if it doesn't exist
        os.makedirs(self.templates_dir, exist_ok=True)
        
        try:
            if os.path.exists(templates_file):
                with open(templates_file, 'r') as f:
                    templates = json.load(f)
            else:
                # Create default templates if file doesn't exist
                templates = self._create_default_templates()
                
                # Save default templates
                with open(templates_file, 'w') as f:
                    json.dump(templates, f, indent=2)
        except Exception as e:
            logger.error(f"Error loading templates: {str(e)}")
            # Create default templates if there's an error
            templates = self._create_default_templates()
            
        return templates
    
    def _create_default_templates(self) -> Dict[str, Dict[str, Any]]:
        """Create default templates for common device types
        
        Returns:
            Dict: Dictionary of default device templates
        """
        return {
            "cisco_ios": {
                "name": "Cisco IOS Router",
                "description": "Template for Cisco IOS routers with secure baseline configuration",
                "base_template": self._get_default_cisco_ios_template(),
                "sections": {
                    "system": {
                        "name": "System Settings",
                        "fields": [
                            {"name": "hostname", "description": "Device hostname", "required": True},
                            {"name": "domain", "description": "Domain name", "required": False},
                            {"name": "timezone", "description": "Device timezone", "default": "UTC", "required": False}
                        ]
                    },
                    "interfaces": {
                        "name": "Network Interfaces",
                        "fields": [
                            {"name": "interfaces", "description": "Network interfaces", "type": "list", "required": True}
                        ]
                    },
                    "routing": {
                        "name": "Routing Configuration",
                        "fields": [
                            {"name": "static_routes", "description": "Static routes", "type": "list", "required": False},
                            {"name": "default_route", "description": "Default route", "required": False}
                        ]
                    },
                    "security": {
                        "name": "Security Settings",
                        "fields": [
                            {"name": "enable_password", "description": "Enable password (encrypted)", "required": True},
                            {"name": "admin_user", "description": "Admin username", "required": True},
                            {"name": "admin_password", "description": "Admin password (encrypted)", "required": True},
                            {"name": "ssh_version", "description": "SSH version", "default": "2", "required": False},
                            {"name": "access_lists", "description": "Access control lists", "type": "list", "required": False}
                        ]
                    }
                }
            },
            "cisco_asa": {
                "name": "Cisco ASA Firewall",
                "description": "Template for Cisco ASA firewalls with secure baseline configuration",
                "base_template": self._get_default_cisco_asa_template(),
                "sections": {
                    "system": {
                        "name": "System Settings",
                        "fields": [
                            {"name": "hostname", "description": "Device hostname", "required": True},
                            {"name": "domain", "description": "Domain name", "required": False}
                        ]
                    },
                    "interfaces": {
                        "name": "Network Interfaces",
                        "fields": [
                            {"name": "interfaces", "description": "Network interfaces", "type": "list", "required": True}
                        ]
                    },
                    "nat": {
                        "name": "NAT Configuration",
                        "fields": [
                            {"name": "nat_rules", "description": "NAT rules", "type": "list", "required": False}
                        ]
                    },
                    "security": {
                        "name": "Security Settings",
                        "fields": [
                            {"name": "enable_password", "description": "Enable password (encrypted)", "required": True},
                            {"name": "admin_user", "description": "Admin username", "required": True},
                            {"name": "admin_password", "description": "Admin password (encrypted)", "required": True},
                            {"name": "access_lists", "description": "Access control lists", "type": "list", "required": True}
                        ]
                    }
                }
            },
            "juniper_junos": {
                "name": "Juniper JunOS",
                "description": "Template for Juniper devices with secure baseline configuration",
                "base_template": self._get_default_juniper_template(),
                "sections": {
                    "system": {
                        "name": "System Settings",
                        "fields": [
                            {"name": "hostname", "description": "Device hostname", "required": True},
                            {"name": "domain", "description": "Domain name", "required": False}
                        ]
                    },
                    "interfaces": {
                        "name": "Network Interfaces",
                        "fields": [
                            {"name": "interfaces", "description": "Network interfaces", "type": "list", "required": True}
                        ]
                    },
                    "routing": {
                        "name": "Routing Configuration",
                        "fields": [
                            {"name": "static_routes", "description": "Static routes", "type": "list", "required": False},
                            {"name": "default_route", "description": "Default route", "required": False}
                        ]
                    },
                    "security": {
                        "name": "Security Settings",
                        "fields": [
                            {"name": "root_password", "description": "Root password (encrypted)", "required": True},
                            {"name": "admin_user", "description": "Admin username", "required": True},
                            {"name": "admin_password", "description": "Admin password (encrypted)", "required": True}
                        ]
                    }
                }
            }
        }
    
    def _get_default_cisco_ios_template(self) -> str:
        """Get default Cisco IOS template
        
        Returns:
            str: Default Cisco IOS configuration template
        """
        return """!
! Configuration generated by Network Security Automation Tool Configuration Wizard
! Generated on: {timestamp}
!
version 15.2
service timestamps debug datetime msec
service timestamps log datetime msec
service password-encryption
!
hostname {hostname}
!
boot-start-marker
boot-end-marker
!
enable secret {enable_password}
!
aaa new-model
!
aaa authentication login default local
aaa authorization exec default local
!
username {admin_user} privilege 15 secret {admin_password}
!
ip domain-name {domain}
ip cef
!
{interfaces}
!
{static_routes}
{default_route}
!
{access_lists}
!
line con 0
 exec-timeout 5 0
line vty 0 4
 exec-timeout 5 0
 transport input ssh
!
! End of configuration
"""
    
    def _get_default_cisco_asa_template(self) -> str:
        """Get default Cisco ASA template
        
        Returns:
            str: Default Cisco ASA configuration template
        """
        return """!
! Configuration generated by Network Security Automation Tool Configuration Wizard
! Generated on: {timestamp}
!
ASA Version 9.8(2)
!
hostname {hostname}
domain-name {domain}
enable password {enable_password} encrypted
!
{interfaces}
!
{access_lists}
!
{nat_rules}
!
username {admin_user} password {admin_password} encrypted privilege 15
!
ssh {ssh_timeout} {ssh_version}
!
! End of configuration
"""
    
    def _get_default_juniper_template(self) -> str:
        """Get default Juniper JunOS template
        
        Returns:
            str: Default Juniper JunOS configuration template
        """
        return """#
# Configuration generated by Network Security Automation Tool Configuration Wizard
# Generated on: {timestamp}
#
system {
    host-name {hostname};
    domain-name {domain};
    root-authentication {
        encrypted-password "{root_password}";
    }
    login {
        user {admin_user} {
            full-name "Administrator";
            uid 2000;
            class super-user;
            authentication {
                encrypted-password "{admin_password}";
            }
        }
    }
    services {
        ssh {
            root-login deny;
            protocol-version v2;
        }
    }
    syslog {
        file messages {
            any notice;
        }
    }
}

{interfaces}

{static_routes}
{default_route}

# End of configuration
"""
    
    def _load_security_recommendations(self) -> Dict[str, List[Dict[str, str]]]:
        """Load security recommendations for different device types
        
        Returns:
            Dict: Dictionary of security recommendations by device type
        """
        return {
            "cisco_ios": [
                {
                    "title": "Enable Password Encryption",
                    "description": "Enable service password-encryption to encrypt passwords in the configuration.",
                    "recommendation": "Add 'service password-encryption' to the global configuration.",
                    "severity": "high"
                },
                {
                    "title": "Disable Unused Services",
                    "description": "Disable unnecessary services that could be exploited.",
                    "recommendation": "Add 'no service tcp-small-servers' and 'no service udp-small-servers' to the global configuration.",
                    "severity": "medium"
                },
                {
                    "title": "Secure VTY Lines",
                    "description": "Secure VTY (Telnet/SSH) lines to prevent unauthorized access.",
                    "recommendation": "Configure 'transport input ssh' and 'exec-timeout 5 0' on all VTY lines.",
                    "severity": "high"
                },
                {
                    "title": "Enable SSH Version 2",
                    "description": "Use SSH version 2 instead of version 1 for secure remote access.",
                    "recommendation": "Configure 'ip ssh version 2' in the global configuration.",
                    "severity": "high"
                },
                {
                    "title": "Configure Login Banner",
                    "description": "Set a login banner to inform users about unauthorized access.",
                    "recommendation": "Add 'banner login ^Unauthorized access is prohibited^' to the global configuration.",
                    "severity": "low"
                }
            ],
            "cisco_asa": [
                {
                    "title": "Enable ASDM Access Restrictions",
                    "description": "Restrict ASDM access to specific management networks.",
                    "recommendation": "Configure 'http <ip> <mask> <interface>' to limit ASDM access.",
                    "severity": "high"
                },
                {
                    "title": "Use Secure SSH Settings",
                    "description": "Configure secure SSH settings for remote management.",
                    "recommendation": "Configure 'ssh timeout 10' and 'ssh version 2' for all management interfaces.",
                    "severity": "high"
                },
                {
                    "title": "Implement Appropriate ACLs",
                    "description": "Use access control lists to filter traffic appropriately.",
                    "recommendation": "Create and apply ACLs to interfaces with restrictive 'deny any any log' as the last rule.",
                    "severity": "high"
                },
                {
                    "title": "Configure Management Access Lists",
                    "description": "Restrict management access to specific networks.",
                    "recommendation": "Use 'management-access' to limit access to the device for management purposes.",
                    "severity": "medium"
                },
                {
                    "title": "Enable Threat Detection",
                    "description": "Enable basic and advanced threat detection features.",
                    "recommendation": "Configure 'threat-detection basic-threat' and 'threat-detection statistics' features.",
                    "severity": "medium"
                }
            ],
            "juniper_junos": [
                {
                    "title": "Restrict Root Login",
                    "description": "Disable root login via SSH for security.",
                    "recommendation": "Configure 'system services ssh root-login deny' in the configuration.",
                    "severity": "high"
                },
                {
                    "title": "Use SSH Version 2",
                    "description": "Use SSH version 2 instead of version 1 for secure remote access.",
                    "recommendation": "Configure 'system services ssh protocol-version v2' in the configuration.",
                    "severity": "high"
                },
                {
                    "title": "Configure Login Message",
                    "description": "Set a login message to inform users about unauthorized access.",
                    "recommendation": "Add 'system login message \"Unauthorized access is prohibited\"' to the configuration.",
                    "severity": "low"
                },
                {
                    "title": "Implement Firewall Filters",
                    "description": "Use firewall filters to restrict access to the device.",
                    "recommendation": "Create and apply firewall filters with appropriate rules to restrict access.",
                    "severity": "high"
                },
                {
                    "title": "Configure System Logging",
                    "description": "Enable system logging to track system events and user activities.",
                    "recommendation": "Configure 'system syslog' with appropriate facilities and severity levels.",
                    "severity": "medium"
                }
            ]
        }
    
    def get_device_templates(self) -> Dict[str, Dict[str, Any]]:
        """Get available device templates
        
        Returns:
            Dict: Dictionary of device templates
        """
        return self.device_templates
    
    def get_template_for_device_type(self, device_type: str) -> Optional[Dict[str, Any]]:
        """Get template for specific device type
        
        Args:
            device_type (str): Device type (e.g. cisco_ios, cisco_asa)
            
        Returns:
            Dict: Template for the specified device type or None if not found
        """
        return self.device_templates.get(device_type)
    
    def get_security_recommendations(self, device_type: str) -> List[Dict[str, str]]:
        """Get security recommendations for specific device type
        
        Args:
            device_type (str): Device type (e.g. cisco_ios, cisco_asa)
            
        Returns:
            List: List of security recommendations for the specified device type
        """
        return self.security_recommendations.get(device_type, [])
    
    def generate_config(self, device_type: str, config_values: Dict[str, Any]) -> str:
        """Generate configuration based on template and provided values
        
        Args:
            device_type (str): Device type (e.g. cisco_ios, cisco_asa)
            config_values (Dict): Configuration values to populate the template
            
        Returns:
            str: Generated configuration
        """
        template = self.get_template_for_device_type(device_type)
        if not template:
            logger.error(f"No template found for device type: {device_type}")
            return f"# No template found for device type: {device_type}"
        
        base_template = template.get('base_template', '')
        
        # Add timestamp to config values
        config_values['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Process interfaces if provided
        interfaces_str = ""
        if 'interfaces' in config_values:
            interfaces = config_values.get('interfaces', [])
            if isinstance(interfaces, list):
                for interface in interfaces:
                    if device_type == 'cisco_ios':
                        interfaces_str += self._format_cisco_ios_interface(interface)
                    elif device_type == 'cisco_asa':
                        interfaces_str += self._format_cisco_asa_interface(interface)
                    elif device_type == 'juniper_junos':
                        interfaces_str += self._format_juniper_interface(interface)
        
        config_values['interfaces'] = interfaces_str
        
        # Process static routes if provided
        static_routes_str = ""
        if 'static_routes' in config_values:
            static_routes = config_values.get('static_routes', [])
            if isinstance(static_routes, list):
                for route in static_routes:
                    if device_type == 'cisco_ios':
                        static_routes_str += f"ip route {route.get('network')} {route.get('mask')} {route.get('next_hop')}\n"
                    elif device_type == 'juniper_junos':
                        static_routes_str += f"routing-options {{\n    static {{\n        route {route.get('network')} next-hop {route.get('next_hop')};\n    }}\n}}\n"
        
        config_values['static_routes'] = static_routes_str
        
        # Process access lists if provided
        access_lists_str = ""
        if 'access_lists' in config_values:
            access_lists = config_values.get('access_lists', [])
            if isinstance(access_lists, list):
                for acl in access_lists:
                    if device_type == 'cisco_ios':
                        access_lists_str += self._format_cisco_ios_acl(acl)
                    elif device_type == 'cisco_asa':
                        access_lists_str += self._format_cisco_asa_acl(acl)
        
        config_values['access_lists'] = access_lists_str
        
        # Process NAT rules if provided (for ASA)
        nat_rules_str = ""
        if device_type == 'cisco_asa' and 'nat_rules' in config_values:
            nat_rules = config_values.get('nat_rules', [])
            if isinstance(nat_rules, list):
                for rule in nat_rules:
                    nat_rules_str += f"nat ({rule.get('source_interface')},{rule.get('destination_interface')}) source dynamic {rule.get('source_network')} {rule.get('translated_address')}\n"
        
        config_values['nat_rules'] = nat_rules_str
        
        # Process default route if provided
        default_route_str = ""
        if 'default_route' in config_values and config_values.get('default_route'):
            default_route = config_values.get('default_route')
            if device_type == 'cisco_ios':
                default_route_str = f"ip route 0.0.0.0 0.0.0.0 {default_route}\n"
            elif device_type == 'juniper_junos':
                default_route_str = f"routing-options {{\n    static {{\n        route 0.0.0.0/0 next-hop {default_route};\n    }}\n}}\n"
        
        config_values['default_route'] = default_route_str
        
        # If any required fields are missing, add a comment
        for section_name, section in template.get('sections', {}).items():
            for field in section.get('fields', []):
                field_name = field.get('name')
                if field.get('required', False) and field_name not in config_values:
                    config_values[field_name] = f"# WARNING: Required field '{field_name}' is missing"
        
        # Replace placeholders in the template
        try:
            return base_template.format(**config_values)
        except KeyError as e:
            logger.error(f"Missing field in template: {str(e)}")
            return f"# Error generating configuration: Missing field {str(e)}"
        except Exception as e:
            logger.error(f"Error generating configuration: {str(e)}")
            return f"# Error generating configuration: {str(e)}"
    
    def _format_cisco_ios_interface(self, interface: Dict[str, Any]) -> str:
        """Format Cisco IOS interface configuration
        
        Args:
            interface (Dict): Interface configuration values
            
        Returns:
            str: Formatted interface configuration
        """
        name = interface.get('name', '')
        ip_address = interface.get('ip_address', '')
        mask = interface.get('mask', '')
        description = interface.get('description', '')
        
        config = f"interface {name}\n"
        if description:
            config += f" description {description}\n"
        if ip_address and mask:
            config += f" ip address {ip_address} {mask}\n"
        config += " no shutdown\n"
        config += "!\n"
        
        return config
    
    def _format_cisco_asa_interface(self, interface: Dict[str, Any]) -> str:
        """Format Cisco ASA interface configuration
        
        Args:
            interface (Dict): Interface configuration values
            
        Returns:
            str: Formatted interface configuration
        """
        name = interface.get('name', '')
        ip_address = interface.get('ip_address', '')
        mask = interface.get('mask', '')
        nameif = interface.get('nameif', '')
        security_level = interface.get('security_level', '0')
        
        config = f"interface {name}\n"
        if nameif:
            config += f" nameif {nameif}\n"
        config += f" security-level {security_level}\n"
        if ip_address and mask:
            config += f" ip address {ip_address} {mask}\n"
        config += " no shutdown\n"
        config += "!\n"
        
        return config
    
    def _format_juniper_interface(self, interface: Dict[str, Any]) -> str:
        """Format Juniper interface configuration
        
        Args:
            interface (Dict): Interface configuration values
            
        Returns:
            str: Formatted interface configuration
        """
        name = interface.get('name', '')
        ip_address = interface.get('ip_address', '')
        mask = interface.get('mask', '')
        description = interface.get('description', '')
        
        config = f"interfaces {{\n    {name} {{\n"
        if description:
            config += f"        description \"{description}\";\n"
        config += "        unit 0 {\n"
        config += "            family inet {\n"
        if ip_address and mask:
            # Convert mask to CIDR notation if needed
            if '.' in mask:  # Subnet mask format (e.g., 255.255.255.0)
                # For simplicity, we'll assume it's already in CIDR format
                config += f"                address {ip_address}/{mask};\n"
            else:  # CIDR format (e.g., 24)
                config += f"                address {ip_address}/{mask};\n"
        config += "            }\n"
        config += "        }\n"
        config += "    }\n"
        config += "}\n"
        
        return config
    
    def _format_cisco_ios_acl(self, acl: Dict[str, Any]) -> str:
        """Format Cisco IOS access control list
        
        Args:
            acl (Dict): Access control list configuration
            
        Returns:
            str: Formatted ACL configuration
        """
        name = acl.get('name', '')
        type_str = acl.get('type', 'standard')
        rules = acl.get('rules', [])
        
        if not name or not rules:
            return ""
        
        if type_str.lower() == 'standard':
            config = f"ip access-list standard {name}\n"
        else:
            config = f"ip access-list extended {name}\n"
        
        for rule in rules:
            action = rule.get('action', 'deny')
            source = rule.get('source', 'any')
            destination = rule.get('destination', '')
            protocol = rule.get('protocol', '')
            log = ' log' if rule.get('log', False) else ''
            
            if type_str.lower() == 'standard':
                config += f" {action} {source}{log}\n"
            else:
                if not destination:
                    destination = 'any'
                if not protocol:
                    protocol = 'ip'
                config += f" {action} {protocol} {source} {destination}{log}\n"
        
        config += "!\n"
        return config
    
    def _format_cisco_asa_acl(self, acl: Dict[str, Any]) -> str:
        """Format Cisco ASA access control list
        
        Args:
            acl (Dict): Access control list configuration
            
        Returns:
            str: Formatted ACL configuration
        """
        name = acl.get('name', '')
        rules = acl.get('rules', [])
        
        if not name or not rules:
            return ""
        
        config = f"access-list {name} extended "
        
        for rule in rules:
            action = rule.get('action', 'deny')
            source = rule.get('source', 'any')
            destination = rule.get('destination', 'any')
            protocol = rule.get('protocol', 'ip')
            log = ' log' if rule.get('log', False) else ''
            
            config += f"{action} {protocol} {source} {destination}{log}\n"
        
        return config
    
    def _initialize_ml_models(self):
        """Initialize or load machine learning models for configuration analysis"""
        try:
            # In a real implementation, we would load pre-trained models from files
            # For this demo, we'll initialize them with defaults
            
            # K-means for clustering similar configurations
            self.kmeans = KMeans(n_clusters=3, random_state=42)
            
            # Random Forest for security score prediction
            self.rf_classifier = RandomForestClassifier(n_estimators=100, random_state=42)
            
            logger.info("Machine learning models initialized successfully")
        except Exception as e:
            logger.error(f"Error initializing ML models: {str(e)}")
    
    def _load_sample_configs(self) -> Dict[str, List[str]]:
        """Load sample configurations for training ML models
        
        Returns:
            Dict: Dictionary of sample configurations by device type
        """
        # In a real implementation, we would load actual configurations
        # For this demo, we'll use the default templates as samples
        samples = {
            "cisco_ios": [self._get_default_cisco_ios_template()],
            "cisco_asa": [self._get_default_cisco_asa_template()],
            "juniper_junos": [self._get_default_juniper_template()]
        }
        
        # Add more variations for better training
        # Cisco IOS variations
        samples["cisco_ios"].append("""!
version 15.2
service timestamps debug datetime msec
service timestamps log datetime msec
service password-encryption
no service tcp-small-servers
no service udp-small-servers
!
hostname SecureRouter
!
boot-start-marker
boot-end-marker
!
enable secret 5 $1$12345$AbCdEfGhIjKlMnOp
!
aaa new-model
!
aaa authentication login default local
aaa authorization exec default local
!
username admin privilege 15 secret 5 $1$12345$AbCdEfGhIjKlMnOp
!
ip domain-name example.com
ip cef
!
ip ssh version 2
ip ssh time-out 60
ip ssh authentication-retries 3
!
logging host 192.168.1.100
logging trap notifications
!
ntp server 192.168.1.200
!
interface GigabitEthernet0/0
 description WAN Connection
 ip address 203.0.113.1 255.255.255.0
 no shutdown
!
interface GigabitEthernet0/1
 description LAN Connection
 ip address 192.168.1.1 255.255.255.0
 no shutdown
!
ip access-list extended INBOUND
 permit tcp any any established
 deny   ip any any log
!
line con 0
 exec-timeout 5 0
line vty 0 4
 exec-timeout 5 0
 transport input ssh
!
banner login ^
Unauthorized access is strictly prohibited and will be prosecuted to the fullest extent of the law.
^
!
end""")

        # Add a less secure configuration variant
        samples["cisco_ios"].append("""!
version 15.2
service timestamps debug datetime msec
service timestamps log datetime msec
!
hostname BasicRouter
!
enable password cisco123
!
username admin password cisco123
!
interface GigabitEthernet0/0
 ip address 203.0.113.1 255.255.255.0
 no shutdown
!
interface GigabitEthernet0/1
 ip address 192.168.1.1 255.255.255.0
 no shutdown
!
ip route 0.0.0.0 0.0.0.0 203.0.113.254
!
line con 0
line vty 0 4
 transport input telnet ssh
 password cisco123
!
end""")
        
        return samples
    
    def _extract_features(self, config: str) -> Dict[str, int]:
        """Extract security features from a configuration
        
        Args:
            config (str): Device configuration
            
        Returns:
            Dict: Dictionary of feature presence (1) or absence (0)
        """
        features = {}
        
        # Check for presence of each pattern
        for feature_name, pattern in self.feature_patterns.items():
            features[feature_name] = 1 if re.search(pattern, config, re.IGNORECASE) else 0
            
        return features
    
    def _vectorize_config(self, config: str) -> np.ndarray:
        """Convert configuration text to feature vector using TF-IDF
        
        Args:
            config (str): Device configuration
            
        Returns:
            np.ndarray: Feature vector
        """
        # Ensure the vectorizer is fit on sample data
        if not hasattr(self.vectorizer, 'vocabulary_'):
            # Combine all sample configs for fitting
            all_samples = []
            for device_samples in self.sample_configs.values():
                all_samples.extend(device_samples)
            
            if all_samples:
                self.vectorizer.fit(all_samples)
            else:
                # Fallback if no samples
                self.vectorizer.fit([config])
        
        # Transform the config into vector
        try:
            # Convert sparse matrix to dense array
            result = self.vectorizer.transform([config])
            return result.toarray()[0] if hasattr(result, 'toarray') else np.array(result[0])
        except Exception as e:
            logger.error(f"Error vectorizing config: {str(e)}")
            # Return empty vector with expected dimensions
            if hasattr(self.vectorizer, 'vocabulary_'):
                return np.zeros(len(self.vectorizer.vocabulary_))
            return np.zeros(100)  # Default size
    
    def _predict_security_score(self, features: Dict[str, int]) -> int:
        """Predict security score based on configuration features
        
        Args:
            features (Dict): Extracted features
            
        Returns:
            int: Predicted security score (0-100)
        """
        # Convert features to array
        feature_array = np.array([list(features.values())])
        
        # In a real implementation, we would use a trained model
        # For this demo, we'll use a simple formula based on feature weights
        feature_weights = {
            'password_encryption': 10,
            'ssh_version': 15,
            'access_list': 15,
            'timeout': 10,
            'banner': 5,
            'logging': 10,
            'ntp': 5,
            'tacacs': 10,
            'snmp': 10,
            'https': 10
        }
        
        score = 0
        for feature, weight in feature_weights.items():
            if feature in features and features[feature] == 1:
                score += weight
        
        return score
    
    def _get_similar_configs(self, config: str, device_type: str, top_n: int = 3) -> List[Tuple[str, float]]:
        """Find similar configurations using cosine similarity
        
        Args:
            config (str): Device configuration
            device_type (str): Device type
            top_n (int): Number of similar configs to return
            
        Returns:
            List[Tuple]: List of tuples (config, similarity_score)
        """
        # Get the sample configs for this device type
        samples = self.sample_configs.get(device_type, [])
        if not samples:
            return []
        
        # Vectorize the input config and samples
        config_vector = self._vectorize_config(config)
        sample_vectors = [self._vectorize_config(sample) for sample in samples]
        
        # Calculate cosine similarity
        similarities = []
        for i, sample_vector in enumerate(sample_vectors):
            sim = cosine_similarity([config_vector], [sample_vector])[0][0]
            similarities.append((samples[i], sim))
        
        # Sort by similarity score (descending) and return top N
        return sorted(similarities, key=lambda x: x[1], reverse=True)[:top_n]
    
    def _suggest_improvements(self, features: Dict[str, int], device_type: str) -> List[Dict[str, str]]:
        """Suggest configuration improvements based on extracted features
        
        Args:
            features (Dict): Extracted features
            device_type (str): Device type
            
        Returns:
            List: List of improvement suggestions
        """
        suggestions = []
        
        # Get base recommendations for this device type
        base_recommendations = self.get_security_recommendations(device_type)
        
        # Create a mapping of features to their respective recommendations
        feature_to_recommendation = {
            'password_encryption': {
                'title': 'Enable Password Encryption',
                'description': 'Password encryption is not enabled, making passwords vulnerable if configuration is accessed.',
                'recommendation': 'Add \'service password-encryption\' to the global configuration.',
                'severity': 'high'
            },
            'ssh_version': {
                'title': 'Configure SSH Version 2',
                'description': 'SSH version 2 is not explicitly configured, which may allow the use of less secure SSH version 1.',
                'recommendation': 'Configure SSH version 2 to improve security.',
                'severity': 'high'
            },
            'access_list': {
                'title': 'Implement Access Lists',
                'description': 'No access control lists (ACLs) are configured to filter network traffic.',
                'recommendation': 'Implement ACLs to restrict access and protect the network.',
                'severity': 'high'
            },
            'timeout': {
                'title': 'Configure Session Timeouts',
                'description': 'Session timeouts are not configured, which could leave idle sessions open indefinitely.',
                'recommendation': 'Configure appropriate timeouts for management sessions.',
                'severity': 'medium'
            },
            'banner': {
                'title': 'Add Login Banner',
                'description': 'No login banner is configured to warn against unauthorized access.',
                'recommendation': 'Add a login banner with appropriate legal text.',
                'severity': 'low'
            },
            'logging': {
                'title': 'Enable Logging',
                'description': 'Logging is not properly configured, limiting visibility into system events.',
                'recommendation': 'Configure logging to track security events and troubleshoot issues.',
                'severity': 'medium'
            },
            'ntp': {
                'title': 'Configure NTP',
                'description': 'Network Time Protocol (NTP) is not configured, which may lead to timestamp inconsistencies.',
                'recommendation': 'Configure NTP to ensure accurate time synchronization.',
                'severity': 'medium'
            },
            'tacacs': {
                'title': 'Implement AAA/TACACS+',
                'description': 'AAA or TACACS+ authentication is not configured for centralized access control.',
                'recommendation': 'Configure AAA/TACACS+ for improved authentication and authorization.',
                'severity': 'high'
            },
            'snmp': {
                'title': 'Secure SNMP Configuration',
                'description': 'SNMP is not properly secured or configured.',
                'recommendation': 'Configure SNMPv3 or secure SNMPv2 with community strings.',
                'severity': 'medium'
            },
            'https': {
                'title': 'Enable HTTPS for Management',
                'description': 'HTTPS is not configured for secure web management.',
                'recommendation': 'Configure HTTPS instead of HTTP for web management access.',
                'severity': 'medium'
            }
        }
        
        # Add suggestions for missing features
        for feature, recommendation in feature_to_recommendation.items():
            if feature in features and features[feature] == 0:
                suggestions.append(recommendation)
        
        return suggestions
    
    def analyze_config(self, device_type: str, config: str) -> Dict[str, Any]:
        """Analyze configuration for potential issues and recommendations using ML techniques
        
        Args:
            device_type (str): Device type (e.g. cisco_ios, cisco_asa)
            config (str): Device configuration to analyze
            
        Returns:
            Dict: Analysis results with recommendations
        """
        results = {
            "issues_found": 0,
            "security_score": 0,
            "recommendations": [],
            "similar_configs": [],
            "ml_analysis": {
                "feature_presence": {},
                "similarity_score": 0
            }
        }
        
        try:
            # Extract features from the configuration
            features = self._extract_features(config)
            results["ml_analysis"]["feature_presence"] = features
            
            # Predict security score
            results["security_score"] = self._predict_security_score(features)
            
            # Get improvement suggestions
            results["recommendations"] = self._suggest_improvements(features, device_type)
            results["issues_found"] = len(results["recommendations"])
            
            # Find similar configurations
            similar_configs = self._get_similar_configs(config, device_type)
            if similar_configs:
                # Just include the similarity score, not the full configs
                results["ml_analysis"]["similarity_score"] = similar_configs[0][1]
                
                # Add recommendation if similarity is low
                if similar_configs[0][1] < 0.5:
                    results["recommendations"].append({
                        "title": "Configuration Deviates from Best Practices",
                        "description": "The current configuration differs significantly from best-practice templates.",
                        "recommendation": "Consider reviewing the suggested template for this device type.",
                        "severity": "medium"
                    })
                    results["issues_found"] += 1
            
            # Ensure security score is valid
            results["security_score"] = max(0, min(100, results["security_score"]))
            
        except Exception as e:
            logger.error(f"Error analyzing configuration: {str(e)}")
            # Fallback to basic analysis
            results["recommendations"].append({
                "title": "Configuration Analysis Error",
                "description": f"An error occurred during advanced analysis: {str(e)}",
                "recommendation": "Please try again or check the configuration format.",
                "severity": "medium"
            })
            results["issues_found"] = 1
            results["security_score"] = 50  # Default middle score
        
        return results
    
    def get_friendly_guidance(self, device_type: str, section: str) -> str:
        """Get friendly guidance for a specific section of the configuration
        
        Args:
            device_type (str): Device type (e.g. cisco_ios, cisco_asa)
            section (str): Configuration section (e.g. system, interfaces, security)
            
        Returns:
            str: Friendly guidance text
        """
        guidance = {
            "cisco_ios": {
                "system": """
<h5>System Settings Tips</h5>
<ul>
    <li>Choose a hostname that reflects the device's role and location</li>
    <li>Set a domain name to enable SSH functionalities</li>
    <li>Configure your timezone to ensure accurate timestamps in logs</li>
</ul>
""",
                "interfaces": """
<h5>Interface Configuration Tips</h5>
<ul>
    <li>Add descriptive names to interfaces to identify their purpose</li>
    <li>Consider using private IP addresses for internal networks (e.g., 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)</li>
    <li>Only enable interfaces that are in use</li>
    <li>Consider using /30 or /31 subnets for point-to-point links to conserve IP space</li>
</ul>
""",
                "routing": """
<h5>Routing Configuration Tips</h5>
<ul>
    <li>Use a default route to simplify routing when possible</li>
    <li>Add static routes only for specific destinations not covered by dynamic routing</li>
    <li>Consider adding a description to static routes for better documentation</li>
</ul>
""",
                "security": """
<h5>Security Best Practices</h5>
<ul>
    <li>Use strong, encrypted passwords</li>
    <li>Create individual user accounts instead of shared credentials</li>
    <li>Enable SSH version 2 and disable Telnet access</li>
    <li>Create access lists to restrict traffic where appropriate</li>
    <li>Enable logging for security events</li>
    <li>Set executive timeouts to automatically disconnect inactive sessions</li>
</ul>
"""
            },
            "cisco_asa": {
                "system": """
<h5>System Settings Tips</h5>
<ul>
    <li>Choose a hostname that reflects the firewall's role</li>
    <li>Set a domain name to enable SSH functionalities</li>
    <li>Consider configuring DNS servers for name resolution</li>
</ul>
""",
                "interfaces": """
<h5>Interface Configuration Tips</h5>
<ul>
    <li>Use meaningful nameif values that represent the security zone (e.g., inside, outside, dmz)</li>
    <li>Set appropriate security levels (0-100) based on the trust level of the network</li>
    <li>Consider using private IP addresses for internal networks</li>
</ul>
""",
                "nat": """
<h5>NAT Configuration Tips</h5>
<ul>
    <li>Use Auto NAT for simple scenarios and Manual NAT for complex requirements</li>
    <li>Consider using PAT (Port Address Translation) to conserve public IP addresses</li>
    <li>Carefully order your NAT rules as they are processed sequentially</li>
</ul>
""",
                "security": """
<h5>Security Best Practices</h5>
<ul>
    <li>Create specific access lists instead of allowing all traffic</li>
    <li>Deny unnecessary traffic and log suspicious activities</li>
    <li>Enable threat detection features</li>
    <li>Implement application inspection for relevant protocols</li>
    <li>Configure SSH for secure management access</li>
    <li>Consider implementing IPS features for additional protection</li>
</ul>
"""
            },
            "juniper_junos": {
                "system": """
<h5>System Settings Tips</h5>
<ul>
    <li>Choose a hostname that reflects the device's role and location</li>
    <li>Configure system services carefully, enabling only what's needed</li>
    <li>Set up NTP for accurate time synchronization</li>
</ul>
""",
                "interfaces": """
<h5>Interface Configuration Tips</h5>
<ul>
    <li>Add descriptive names to interfaces using the 'description' field</li>
    <li>Use family inet for IPv4 configuration</li>
    <li>Consider using VLAN tagging for trunk interfaces</li>
</ul>
""",
                "routing": """
<h5>Routing Configuration Tips</h5>
<ul>
    <li>Place static routes in the routing-options hierarchy</li>
    <li>Consider using route preferences to prioritize routing sources</li>
    <li>Use routing instances for traffic separation where needed</li>
</ul>
""",
                "security": """
<h5>Security Best Practices</h5>
<ul>
    <li>Use strong, encrypted passwords for root and user accounts</li>
    <li>Disable root login via SSH</li>
    <li>Implement firewall filters to restrict management access</li>
    <li>Enable system logging to track security events</li>
    <li>Consider implementing security policies if using SRX series devices</li>
</ul>
"""
            }
        }
        
        # Get guidance for device type and section, or return a generic message
        return guidance.get(device_type, {}).get(section, """
<h5>Configuration Tips</h5>
<p>Complete the fields in this section according to your network requirements.</p>
<p>Refer to vendor documentation for specific guidance on this device type.</p>
""")

# Export wizard instance
wizard = ConfigWizard()