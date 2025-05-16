"""
Test data generator for network security automation tool
This utility creates simulated test data for demonstration purposes
"""
import random
import json
import math
from datetime import datetime, timedelta
import threading
import time
from typing import Dict, List, Optional, Tuple, Any


class TestDataGenerator:
    """Class for generating test data for the application"""
    
    def __init__(self):
        """Initialize the test data generator"""
        self.running = False
        self.thread = None
        self.callbacks = {}
        
    def start(self, interval: float = 2.0):
        """Start the test data generation thread
        
        Args:
            interval (float): Interval between data generations in seconds
        """
        if self.running:
            return
            
        self.running = True
        self.thread = threading.Thread(target=self._generate_loop, args=(interval,))
        self.thread.daemon = True
        self.thread.start()
        
    def stop(self):
        """Stop the test data generation thread"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=1.0)
            
    def register_callback(self, name: str, callback):
        """Register a callback function for receiving generated data
        
        Args:
            name (str): Name of the callback
            callback (callable): Function to call with generated data
        """
        self.callbacks[name] = callback
        
    def unregister_callback(self, name: str):
        """Unregister a callback function
        
        Args:
            name (str): Name of the callback to remove
        """
        if name in self.callbacks:
            del self.callbacks[name]
            
    def _generate_loop(self, interval: float):
        """Main loop for periodically generating test data
        
        Args:
            interval (float): Interval between data generations in seconds
        """
        while self.running:
            # Generate data
            data = {
                'timestamp': datetime.now().isoformat(),
                'devices': self._generate_device_data()
            }
            
            # Call all registered callbacks
            for callback in self.callbacks.values():
                try:
                    callback(data)
                except Exception as e:
                    print(f"Error in test data callback: {str(e)}")
                    
            # Sleep for interval
            time.sleep(interval)
            
    def _generate_device_data(self) -> List[Dict[str, Any]]:
        """Generate test data for devices
        
        Returns:
            List[Dict[str, Any]]: List of device data dictionaries
        """
        # Get current time for timestamp consistency
        now = datetime.now()
        
        # Generate random trend patterns for more realistic data
        time_factor = now.timestamp() / 100.0
        sine_factor = (math.sin(time_factor / 5) + 1) * 0.5  # 0 to 1 sine wave
        
        # Random fluctuation levels
        fluctuation = random.uniform(0.8, 1.2)
        
        devices = []
        # Generate data for 3 sample devices
        for device_id in range(1, 4):
            # Create device-specific randomness for variety
            device_factor = device_id * 0.5 
            
            # Random baseline network quality variations by device
            baseline_quality = random.uniform(0.7, 0.95)
            
            # Calculate ping latency with trend and randomness
            base_latency = 20 + (device_id * 10)  # Different baseline for each device
            latency_variance = 15 * sine_factor * fluctuation
            latency = max(1.0, base_latency + (latency_variance * device_factor))
            
            # Calculate packet loss with trend and randomness
            # Sometimes, randomly increase packet loss for simulated issues
            packet_loss = 0
            if random.random() < 0.1:  # 10% chance of packet loss
                packet_loss = random.uniform(1, 10) * (1 - baseline_quality)
                
            # Determine status based on metrics
            status = "up"
            if packet_loss > 5:
                status = "degraded"
            if packet_loss > 20:
                status = "down"
                
            # Generate security metrics
            security_score = 70 + (random.uniform(-10, 30) * baseline_quality)
            security_issues = []
            if security_score < 90:
                security_issues.append("weak_passwords")
            if security_score < 80:
                security_issues.append("unnecessary_services")
            if security_score < 70:
                security_issues.append("outdated_firmware")
                
            # Assembly device data dictionary
            device_data = {
                'device_id': device_id,
                'telemetry': {
                    'latency_ms': round(latency, 2),
                    'packet_loss': round(packet_loss, 1),
                    'status': status,
                    'timestamp': now.isoformat()
                },
                'security': {
                    'score': round(security_score, 1),
                    'issues': security_issues,
                    'last_audit': (now - timedelta(hours=random.randint(1, 24))).isoformat()
                },
                'config_changes': random.randint(0, 5)
            }
            
            devices.append(device_data)
            
        return devices
        
    def generate_history(self, device_id: int, hours: int = 24, points: int = 50) -> Dict[str, Any]:
        """Generate historical ping data for a device
        
        Args:
            device_id (int): Device ID
            hours (int): Hours of history to generate
            points (int): Number of data points to generate
            
        Returns:
            Dict[str, Any]: Historical data dictionary
        """
        now = datetime.now()
        timestamps = []
        latencies = []
        packet_losses = []
        
        # Create device-specific randomness for variety
        device_factor = device_id * 0.5
        
        # Generate data points evenly spaced over the time period
        for i in range(points):
            # Calculate time for this point
            point_time = now - timedelta(hours=hours * (points - i) / points)
            timestamps.append(point_time.isoformat())
            
            # Calculate metrics with some randomness and patterns
            time_factor = point_time.timestamp() / 3600.0
            sine_factor = (math.sin(time_factor / 5) + 1) * 0.5
            
            # Generate latency with time-based pattern
            base_latency = 20 + (device_id * 10)
            latency_variance = 15 * sine_factor
            latency = max(1.0, base_latency + (latency_variance * device_factor))
            latency += random.uniform(-5, 5)  # Add some noise
            latencies.append(round(latency, 2))
            
            # Generate packet loss with occasional spikes
            packet_loss = 0
            if random.random() < 0.15:  # 15% chance of packet loss
                packet_loss = random.uniform(1, 10)
            packet_losses.append(round(packet_loss, 1))
            
        return {
            'device_id': device_id,
            'timestamps': timestamps,
            'latencies': latencies,
            'packet_losses': packet_losses
        }
        
    def generate_security_audit(self, device_id: int) -> Dict[str, Any]:
        """Generate a simulated security audit for a device
        
        Args:
            device_id (int): Device ID
            
        Returns:
            Dict[str, Any]: Security audit data
        """
        # Create device-specific baseline for consistency
        random.seed(device_id)
        baseline_security = random.uniform(0.6, 0.9)
        random.seed()  # Reset randomness
        
        # Generate security score with some randomness
        security_score = 70 + (random.uniform(-10, 30) * baseline_security)
        
        # Categories of security checks
        categories = ['password_policy', 'access_controls', 'services', 'firmware', 'logging']
        
        # Generate results for each category
        results = {}
        total_checks = 0
        passed_checks = 0
        
        for category in categories:
            checks = []
            # Number of checks for this category
            num_checks = random.randint(2, 5)
            
            for i in range(num_checks):
                # Determine result with weighted randomness
                passed = random.random() < baseline_security
                if passed:
                    passed_checks += 1
                total_checks += 1
                
                checks.append({
                    'id': f"{category}_{i+1}",
                    'description': f"Test {category} check #{i+1}",
                    'result': 'pass' if passed else 'fail',
                    'details': self._generate_check_details(category, passed)
                })
                
            results[category] = {
                'name': category.replace('_', ' ').title(),
                'checks': checks
            }
            
        return {
            'device_id': device_id,
            'timestamp': datetime.now().isoformat(),
            'score': round(security_score, 1),
            'passed_checks': passed_checks,
            'total_checks': total_checks,
            'results': results
        }
        
    def _generate_check_details(self, category: str, passed: bool) -> str:
        """Generate human-readable details for a security check
        
        Args:
            category (str): Check category
            passed (bool): Whether the check passed
            
        Returns:
            str: Human-readable details text
        """
        if category == 'password_policy':
            if passed:
                return random.choice([
                    "Password policy meets minimum complexity requirements",
                    "Passwords are encrypted with strong algorithms",
                    "Password expiration policy is properly configured"
                ])
            else:
                return random.choice([
                    "Password policy does not require sufficient complexity",
                    "Passwords are stored with weak encryption",
                    "Password expiration is not configured"
                ])
                
        elif category == 'access_controls':
            if passed:
                return random.choice([
                    "Access control lists are properly configured",
                    "SSH access is restricted to authorized networks",
                    "Unused ports are disabled"
                ])
            else:
                return random.choice([
                    "Access control lists allow excessive traffic",
                    "SSH access is allowed from any IP address",
                    "Multiple unused ports are open"
                ])
                
        elif category == 'services':
            if passed:
                return random.choice([
                    "Only necessary services are running",
                    "Services are running with least privileges",
                    "Service authentication is properly configured"
                ])
            else:
                return random.choice([
                    "Multiple unnecessary services are running",
                    "Services are running with excessive privileges",
                    "Service authentication uses default credentials"
                ])
                
        elif category == 'firmware':
            if passed:
                return random.choice([
                    "Firmware is up to date",
                    "Automatic updates are enabled",
                    "No known vulnerabilities in current firmware version"
                ])
            else:
                return random.choice([
                    "Firmware is outdated by multiple versions",
                    "Automatic updates are disabled",
                    "Current firmware has known security vulnerabilities"
                ])
                
        elif category == 'logging':
            if passed:
                return random.choice([
                    "Logging is properly configured and enabled",
                    "Logs are sent to a secure SYSLOG server",
                    "Log retention policy is configured correctly"
                ])
            else:
                return random.choice([
                    "Logging is minimal or disabled",
                    "Logs are only stored locally",
                    "Log retention is insufficient"
                ])
                
        else:
            if passed:
                return "Check passed successfully"
            else:
                return "Check failed"