# Security checking functionality
import re
import logging
from utils.device_connector import DeviceConnector

logger = logging.getLogger(__name__)

class SecurityChecker:
    """Class to perform security checks on network devices"""
    
    def __init__(self):
        """Initialize the security checker"""
        pass
    
    def check_password_policy(self, connector):
        """Check password policies on the device
        
        Args:
            connector (DeviceConnector): Device connector object
        
        Returns:
            dict: Results of the password policy check
        """
        print("\n=== Password Policy Check ===")
        
        results = {
            'min_length': False,
            'complexity': False,
            'encryption': False
        }
        
        try:
            if connector.device_type.startswith('cisco_ios'):
                # Check password minimum length
                output = connector.execute_command('show running-config | include password')
                
                # Check for minimum length configuration
                min_length_output = connector.execute_command('show running-config | include security passwords min-length')
                if 'min-length' in min_length_output:
                    min_length = re.search(r'min-length (\d+)', min_length_output)
                    if min_length and int(min_length.group(1)) >= 8:
                        results['min_length'] = True
                        print("✅ Password minimum length is properly configured")
                    else:
                        print("❌ Password minimum length should be at least 8 characters")
                else:
                    print("❌ Password minimum length is not configured")
                
                # Check password complexity
                complexity_output = connector.execute_command('show running-config | include password complexity')
                if 'complexity' in complexity_output:
                    results['complexity'] = True
                    print("✅ Password complexity is enabled")
                else:
                    print("❌ Password complexity is not enabled")
                
                # Check for password encryption
                service_pass_output = connector.execute_command('show running-config | include service password')
                if 'service password-encryption' in service_pass_output:
                    results['encryption'] = True
                    print("✅ Password encryption is enabled")
                else:
                    print("❌ Password encryption is not enabled")
            
            elif connector.device_type.startswith('juniper'):
                # Juniper password policy checks
                output = connector.execute_command('show configuration system login')
                
                # Check password minimum length and complexity
                if 'minimum-length' in output:
                    min_length = re.search(r'minimum-length (\d+)', output)
                    if min_length and int(min_length.group(1)) >= 8:
                        results['min_length'] = True
                        print("✅ Password minimum length is properly configured")
                    else:
                        print("❌ Password minimum length should be at least 8 characters")
                else:
                    print("❌ Password minimum length is not configured")
                
                if 'at-least-one-uppercase' in output and 'at-least-one-lowercase' in output and 'at-least-one-digit' in output:
                    results['complexity'] = True
                    print("✅ Password complexity requirements are configured")
                else:
                    print("❌ Password complexity requirements are not fully configured")
                
                # Juniper encrypts passwords by default
                results['encryption'] = True
                print("✅ Password encryption is enabled by default")
            
            else:
                print(f"⚠️ Password policy check not implemented for device type: {connector.device_type}")
            
        except Exception as e:
            logger.error(f"Error checking password policy: {str(e)}")
            print(f"❌ Error checking password policy: {str(e)}")
        
        return results
    
    def check_access_controls(self, connector):
        """Check access control configurations
        
        Args:
            connector (DeviceConnector): Device connector object
        
        Returns:
            dict: Results of the access control check
        """
        print("\n=== Access Control Check ===")
        
        results = {
            'ssh_enabled': False,
            'telnet_disabled': False,
            'acl_applied': False,
            'unused_accounts': []
        }
        
        try:
            if connector.device_type.startswith('cisco_ios'):
                # Check if SSH is enabled and Telnet is disabled
                line_output = connector.execute_command('show running-config | section line vty')
                
                if 'transport input ssh' in line_output:
                    results['ssh_enabled'] = True
                    results['telnet_disabled'] = True
                    print("✅ SSH is enabled and Telnet is disabled")
                elif 'transport input telnet ssh' in line_output or 'transport input all' in line_output:
                    results['ssh_enabled'] = True
                    print("✅ SSH is enabled")
                    print("❌ Telnet is enabled (security risk)")
                else:
                    print("❌ SSH configuration is not properly set")
                
                # Check for ACLs on VTY lines
                if 'access-class' in line_output:
                    results['acl_applied'] = True
                    print("✅ Access control lists are applied to VTY lines")
                else:
                    print("❌ No access control lists found on VTY lines")
                
                # Check user accounts
                user_output = connector.execute_command('show running-config | include username')
                if user_output:
                    print("ℹ️ User accounts found:")
                    for line in user_output.splitlines():
                        if line.strip():
                            print(f"  - {line.strip()}")
            
            elif connector.device_type.startswith('juniper'):
                # Check SSH and Telnet for Juniper
                system_services = connector.execute_command('show configuration system services')
                
                if 'ssh' in system_services:
                    results['ssh_enabled'] = True
                    print("✅ SSH is enabled")
                else:
                    print("❌ SSH is not enabled")
                
                if 'telnet' in system_services:
                    print("❌ Telnet is enabled (security risk)")
                else:
                    results['telnet_disabled'] = True
                    print("✅ Telnet is disabled")
                
                # Check for firewall filters on management interfaces
                if 'firewall filter' in system_services:
                    results['acl_applied'] = True
                    print("✅ Firewall filters are applied to management interfaces")
                else:
                    print("❌ No firewall filters found on management interfaces")
                
                # Check user accounts
                user_output = connector.execute_command('show configuration system login user')
                if user_output:
                    print("ℹ️ User accounts found:")
                    users = re.findall(r'user (\w+) {', user_output)
                    for user in users:
                        print(f"  - {user}")
            
            else:
                print(f"⚠️ Access control check not implemented for device type: {connector.device_type}")
        
        except Exception as e:
            logger.error(f"Error checking access controls: {str(e)}")
            print(f"❌ Error checking access controls: {str(e)}")
        
        return results
    
    def check_unnecessary_services(self, connector):
        """Check for unnecessary or vulnerable services
        
        Args:
            connector (DeviceConnector): Device connector object
        
        Returns:
            dict: Results of the service check
        """
        print("\n=== Unnecessary Services Check ===")
        
        results = {
            'cdp_disabled': False,
            'http_disabled': False,
            'snmp_secure': False
        }
        
        try:
            if connector.device_type.startswith('cisco_ios'):
                # Check CDP status
                cdp_output = connector.execute_command('show running-config | include cdp run')
                if 'no cdp run' in cdp_output:
                    results['cdp_disabled'] = True
                    print("✅ CDP is disabled globally")
                else:
                    print("❌ CDP is enabled globally (potential security risk)")
                
                # Check HTTP/HTTPS server status
                http_output = connector.execute_command('show running-config | include http server')
                if 'no ip http server' in http_output:
                    results['http_disabled'] = True
                    print("✅ HTTP server is disabled")
                else:
                    print("❌ HTTP server is enabled (potential security risk)")
                
                # Check SNMP configuration
                snmp_output = connector.execute_command('show running-config | section snmp-server')
                if 'snmp-server community' in snmp_output:
                    # Look for public/private communities
                    if 'community public' in snmp_output or 'community private' in snmp_output:
                        print("❌ Default SNMP communities (public/private) are used")
                    else:
                        # Check for SNMPv3
                        if 'snmp-server group' in snmp_output and 'snmp-server user' in snmp_output and 'priv' in snmp_output:
                            results['snmp_secure'] = True
                            print("✅ SNMPv3 with privacy is configured")
                        else:
                            print("⚠️ SNMP is configured but not using SNMPv3 with privacy")
                else:
                    print("ℹ️ SNMP is not configured")
                    results['snmp_secure'] = True  # No SNMP = no SNMP security risk
            
            elif connector.device_type.startswith('juniper'):
                # Check for protocols in Juniper
                protocols_output = connector.execute_command('show configuration protocols')
                
                # Check for LLDP (Similar to CDP)
                if 'lldp {' in protocols_output:
                    print("❌ LLDP is enabled (potential security risk)")
                else:
                    results['cdp_disabled'] = True
                    print("✅ LLDP is disabled")
                
                # Check HTTP/HTTPS
                http_output = connector.execute_command('show configuration system services web-management')
                if 'http {' in http_output:
                    print("❌ HTTP service is enabled (potential security risk)")
                else:
                    results['http_disabled'] = True
                    print("✅ HTTP service is disabled")
                
                # Check SNMP configuration
                snmp_output = connector.execute_command('show configuration snmp')
                if 'community' in snmp_output:
                    # Look for public/private communities
                    if 'community public' in snmp_output or 'community private' in snmp_output:
                        print("❌ Default SNMP communities (public/private) are used")
                    else:
                        # Check for SNMPv3
                        if 'usm' in snmp_output and 'authentication-sha' in snmp_output and 'privacy-aes128' in snmp_output:
                            results['snmp_secure'] = True
                            print("✅ SNMPv3 with authentication and privacy is configured")
                        else:
                            print("⚠️ SNMP is configured but not using secure SNMPv3 options")
                else:
                    print("ℹ️ SNMP is not configured")
                    results['snmp_secure'] = True  # No SNMP = no SNMP security risk
            
            else:
                print(f"⚠️ Service check not implemented for device type: {connector.device_type}")
        
        except Exception as e:
            logger.error(f"Error checking services: {str(e)}")
            print(f"❌ Error checking services: {str(e)}")
        
        return results
    
    def perform_full_audit(self, connector):
        """Perform a full security audit on the device
        
        Args:
            connector (DeviceConnector): Device connector object
        
        Returns:
            dict: Results of all security checks
        """
        print(f"\n==== SECURITY AUDIT: {connector.ip} ====")
        
        results = {}
        
        # Run all checks
        results['password_policy'] = self.check_password_policy(connector)
        results['access_controls'] = self.check_access_controls(connector)
        results['services'] = self.check_unnecessary_services(connector)
        
        # Check for any open security issues
        issues_found = 0
        
        # Count issues in password policy
        if not results['password_policy']['min_length']:
            issues_found += 1
        if not results['password_policy']['complexity']:
            issues_found += 1
        if not results['password_policy']['encryption']:
            issues_found += 1
        
        # Count issues in access controls
        if not results['access_controls']['ssh_enabled']:
            issues_found += 1
        if not results['access_controls']['telnet_disabled']:
            issues_found += 1
        if not results['access_controls']['acl_applied']:
            issues_found += 1
        
        # Count issues in services
        if not results['services']['cdp_disabled']:
            issues_found += 1
        if not results['services']['http_disabled']:
            issues_found += 1
        if not results['services']['snmp_secure']:
            issues_found += 1
        
        print(f"\n==== AUDIT SUMMARY ====")
        print(f"Issues found: {issues_found}")
        
        if issues_found == 0:
            print("✅ Device passed all security checks!")
        else:
            print("⚠️ Device has security issues that need to be addressed.")
        
        return results
