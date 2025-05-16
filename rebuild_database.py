#!/usr/bin/env python3
"""
Database Rebuild Script

This script completely rebuilds the database for the Network Security Automation Tool:
1. Drops all tables
2. Recreates the database from scratch
3. Sets up users with compatible password hashing
4. Creates sample devices and data

Author: Joel Aaron Guff
"""

import os
import logging
import json
from datetime import datetime
from werkzeug.security import generate_password_hash
from app_init import app, db
from models import User, Device, SecurityAudit, ConfigBackup, PingTelemetry, DeviceConnection

# Configure logging
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Sample device configurations for the demo
DEVICE_CONFIGS = {
    "cisco_ios": """!
hostname ROUTER-1
!
interface GigabitEthernet0/0
 ip address 192.168.1.1 255.255.255.0
 no shutdown
!
interface GigabitEthernet0/1
 ip address 10.0.0.1 255.255.255.0
 no shutdown
!
ip route 0.0.0.0 0.0.0.0 192.168.1.254
!
line vty 0 4
 password cisco
 login
 transport input ssh
!
end""",
    "cisco_asa": """!
hostname FIREWALL-1
!
interface GigabitEthernet0/0
 nameif outside
 security-level 0
 ip address 203.0.113.2 255.255.255.0
!
interface GigabitEthernet0/1
 nameif inside
 security-level 100
 ip address 192.168.1.254 255.255.255.0
!
access-list OUTSIDE_IN extended permit tcp any host 203.0.113.2 eq https
access-list OUTSIDE_IN extended deny ip any any log
!
end"""
}

# Sample audit results for the demo
AUDIT_RESULTS = {
    "cisco_ios": {
        "password_policies": {"status": "warning", "details": "Some passwords are not encrypted"},
        "access_controls": {"status": "pass", "details": "Access control lists properly configured"},
        "authentication": {"status": "fail", "details": "Weak authentication methods in use"},
        "encryption": {"status": "pass", "details": "SSH using strong encryption"}
    },
    "cisco_asa": {
        "password_policies": {"status": "pass", "details": "All passwords are properly secured"},
        "access_controls": {"status": "pass", "details": "Firewall rules properly configured"},
        "authentication": {"status": "warning", "details": "Consider enabling MFA"},
        "encryption": {"status": "pass", "details": "Strong encryption in use for all services"}
    }
}

def rebuild_database():
    """Rebuild the entire database from scratch"""
    with app.app_context():
        try:
            # Drop all tables
            logger.info("Dropping all tables...")
            db.drop_all()
            
            # Recreate all tables
            logger.info("Recreating database tables...")
            db.create_all()
            
            # Create users with proper password hashing (pbkdf2:sha256 instead of scrypt)
            logger.info("Creating users with compatible password hashing...")
            
            # Admin user
            admin = User(
                username='admin',
                email='admin@example.com',
                password_hash=generate_password_hash('admin', method='pbkdf2:sha256', salt_length=16)
            )
            db.session.add(admin)
            
            # Demo user
            demo = User(
                username='demo',
                email='demo@example.com',
                password_hash=generate_password_hash('demo123', method='pbkdf2:sha256', salt_length=16)
            )
            db.session.add(demo)
            
            # Create sample devices
            logger.info("Creating sample network devices...")
            devices = {
                "router1": Device(
                    name="Core Router",
                    ip_address="192.168.1.1",
                    device_type="cisco_ios",
                    username="admin",
                    password="cisco123"
                ),
                "firewall1": Device(
                    name="Edge Firewall",
                    ip_address="203.0.113.2",
                    device_type="cisco_asa",
                    username="admin",
                    password="asa123"
                ),
                "switch1": Device(
                    name="Access Switch",
                    ip_address="192.168.2.1",
                    device_type="cisco_ios",
                    username="admin",
                    password="switch123"
                )
            }
            
            for device in devices.values():
                db.session.add(device)
            
            # Commit to get device IDs
            db.session.commit()
            
            # Create configuration backups
            logger.info("Creating sample configuration backups...")
            for device in devices.values():
                config_text = DEVICE_CONFIGS.get(device.device_type, "# No configuration available")
                backup = ConfigBackup(
                    device_id=device.id,
                    config=config_text
                )
                db.session.add(backup)
            
            # Create security audits
            logger.info("Creating sample security audit reports...")
            for device in devices.values():
                audit_data = AUDIT_RESULTS.get(device.device_type, {})
                if audit_data:
                    # Calculate simple audit score and checks
                    statuses = [item["status"] for item in audit_data.values()]
                    passed = statuses.count("pass")
                    total = len(statuses)
                    score = (passed / total) * 100 if total > 0 else 0
                    
                    audit = SecurityAudit(
                        device_id=device.id,
                        results=json.dumps(audit_data),
                        score=score,
                        passed_checks=passed,
                        total_checks=total
                    )
                    db.session.add(audit)
            
            # Create network connections for topology
            logger.info("Creating sample network topology...")
            connections = [
                # Router to Firewall
                DeviceConnection(
                    source_device_id=devices["router1"].id,
                    target_device_id=devices["firewall1"].id,
                    connection_type="ethernet",
                    interface_source="GigabitEthernet0/0",
                    interface_target="GigabitEthernet0/1",
                    status="active",
                    bandwidth=1000
                ),
                # Router to Switch
                DeviceConnection(
                    source_device_id=devices["router1"].id,
                    target_device_id=devices["switch1"].id,
                    connection_type="ethernet",
                    interface_source="GigabitEthernet0/1",
                    interface_target="GigabitEthernet0/1",
                    status="active",
                    bandwidth=1000
                )
            ]
            
            for connection in connections:
                db.session.add(connection)
            
            # Create ping telemetry data
            logger.info("Creating sample ping telemetry data...")
            for device in devices.values():
                # Generate some sample ping data
                for i in range(24):  # Last 24 hours
                    # Simulate some variance in ping times
                    latency = 5.0 + (0.5 * i % 10)
                    loss = 0.0 if i % 12 != 0 else 5.0  # Occasional packet loss
                    
                    telemetry = PingTelemetry(
                        device_id=device.id,
                        latency_ms=latency,
                        packet_loss=loss,
                        status="up" if loss < 10.0 else "degraded"
                    )
                    db.session.add(telemetry)
            
            # Commit all changes
            db.session.commit()
            logger.info("Database rebuilt successfully")
            logger.info("Demo user credentials: demo / demo123")
            
            return True
        except Exception as e:
            logger.error(f"Error rebuilding database: {e}")
            return False

if __name__ == "__main__":
    logger.info("Starting database rebuild...")
    if rebuild_database():
        logger.info("Database rebuild completed successfully")
    else:
        logger.error("Failed to rebuild database")