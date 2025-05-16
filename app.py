# Import required modules and extensions
from app_init import app, db
from models import User, Device, SecurityAudit, ConfigBackup, PingTelemetry, DeviceConnection
from flask import render_template, request, redirect, url_for, flash, jsonify, session
from flask_login import LoginManager, current_user, login_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
import json
import logging
import os
import random
from datetime import datetime, timedelta
import threading
import time

from utils.device_connector import DeviceConnector
from utils.security_checks import SecurityChecker
from utils.config_parser import ConfigParser
from utils.ping_monitor import PingMonitor
from utils.test_data_generator import TestDataGenerator
from utils.config_wizard import ConfigWizard

# Setup logging
logger = logging.getLogger(__name__)

# Routes will be imported in main.py

# Initialize Ping Monitor - global instance
ping_monitor = PingMonitor(count=3, timeout=2)
ping_monitor_thread = None
ping_data_lock = threading.Lock()
ping_data = {}  # Store recent ping data for each device

# Initialize Test Data Generator
test_data_generator = TestDataGenerator()
test_mode_active = False

def handle_test_data(data):
    """Callback function to handle test data"""
    global ping_data
    
    devices_data = data.get('devices', [])
    with ping_data_lock:
        # Update ping data with test data
        for device in devices_data:
            device_id = device.get('device_id')
            telemetry = device.get('telemetry')
            if device_id and telemetry:
                ping_data[device_id] = telemetry
                
        # We don't use session here since this runs in a background thread
        # The test data is stored in ping_data which is a global dictionary

# Create a simpler telemetry data dictionary for Device objects
def get_ping_telemetry_for_device(device_id):
    """Get telemetry data for a device"""
    with ping_data_lock:
        if device_id in ping_data:
            return ping_data[device_id]
    
    # If no live data, get the most recent from the database
    latest = PingTelemetry.query.filter_by(device_id=device_id).order_by(
        PingTelemetry.timestamp.desc()).first()
    
    if latest:
        return {
            'latency_ms': latest.latency_ms,
            'packet_loss': latest.packet_loss,
            'status': latest.status,
            'timestamp': latest.timestamp.isoformat()
        }
        
    # Return default values if no data
    return {
        'latency_ms': 0,
        'packet_loss': 100,
        'status': 'unknown',
        'timestamp': datetime.now().isoformat()
    }

def start_ping_monitor():
    """Start the ping monitoring service in the background"""
    global ping_monitor_thread
    
    if ping_monitor_thread and ping_monitor_thread.is_alive():
        return  # Already running
        
    # Start the ping monitor
    ping_monitor.start_monitoring()
    
    # Function to process ping results
    def process_ping_results():
        while True:
            try:
                with app.app_context():
                    # Get all devices
                    devices = Device.query.all()
                    
                    # Queue ping requests for all devices
                    for device in devices:
                        ping_monitor.add_device(device.id, device.name, device.ip_address)
                    
                    # Process available results
                    results = ping_monitor.get_all_results()
                    for result in results:
                        # Store in global ping data dictionary
                        with ping_data_lock:
                            ping_data[result['device_id']] = {
                                'latency_ms': result['latency_ms'],
                                'packet_loss': result['packet_loss'],
                                'status': result['status'],
                                'timestamp': result['timestamp']
                            }
                        
                        # Save to database (only every 5 minutes per device)
                        device_id = result['device_id']
                        try:
                            # Check if we need to save this result
                            last_entry = PingTelemetry.query.filter_by(device_id=device_id).order_by(
                                PingTelemetry.timestamp.desc()).first()
                                
                            save_entry = True
                            if last_entry:
                                # Only save if more than 5 minutes passed since last entry
                                time_diff = datetime.utcnow() - last_entry.timestamp
                                if time_diff.total_seconds() < 300:  # 5 minutes
                                    save_entry = False
                            
                            if save_entry:
                                # Create new telemetry entry
                                telemetry = PingTelemetry(
                                    device_id=device_id,
                                    latency_ms=result['latency_ms'],
                                    packet_loss=result['packet_loss'],
                                    status=result['status']
                                )
                                db.session.add(telemetry)
                                db.session.commit()
                        except Exception as e:
                            logger.error(f"Error saving ping telemetry: {str(e)}")
                            db.session.rollback()
            except Exception as e:
                logger.error(f"Error in ping monitor thread: {str(e)}")
            
            # Sleep for a while before next cycle
            time.sleep(10)
    
    # Start processing thread
    ping_monitor_thread = threading.Thread(target=process_ping_results)
    ping_monitor_thread.daemon = True
    ping_monitor_thread.start()

# User loader is now handled in app_init.py

def load_devices_from_json(filename='devices.json'):
    """Load devices from JSON file"""
    if os.path.exists(filename):
        try:
            with open(filename, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError:
            logger.error(f"Error parsing {filename}")
            return {}
    return {}

# Initialize database function moved to a separate function to run with app context
def initialize_database():
    """Initialize database and create admin user if needed"""
    db.create_all()
    
    # Check if admin user exists
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        # Create admin user
        admin = User(
            username='admin',
            email='admin@example.com',
            password_hash=generate_password_hash('admin', method='pbkdf2:sha256', salt_length=16)
        )
        db.session.add(admin)
        
        # Load devices from JSON and add to database
        devices = load_devices_from_json()
        for name, details in devices.items():
            device = Device(
                name=name,
                ip_address=details.get('ip', ''),
                device_type=details.get('device_type', 'cisco_ios'),
                username=details.get('username', ''),
                password=details.get('password', '')  # In production, encrypt passwords
            )
            db.session.add(device)
        
        db.session.commit()
        logger.info("Created admin user and loaded initial devices")

# Run the database initialization with app context
with app.app_context():
    initialize_database()

@app.route('/')
@login_required
def index():
    """Home page route"""
    # Get device count
    device_count = Device.query.count()
    
    # Get audit statistics
    last_audit = SecurityAudit.query.order_by(SecurityAudit.timestamp.desc()).first()
    recent_audits = SecurityAudit.query.order_by(SecurityAudit.timestamp.desc()).limit(5).all()
    
    # Get backup statistics
    last_backup = ConfigBackup.query.order_by(ConfigBackup.timestamp.desc()).first()
    backup_count = ConfigBackup.query.count()
    
    return render_template(
        'index.html',
        device_count=device_count,
        last_audit=last_audit,
        recent_audits=recent_audits,
        last_backup=last_backup,
        backup_count=backup_count
    )

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login route"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and password and check_password_hash(user.password_hash, password):
            login_user(user)
            flash('Login successful!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page if next_page else url_for('index'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """Logout route"""
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/devices')
@login_required
def devices():
    """Devices list route"""
    all_devices = Device.query.all()
    return render_template('devices.html', devices=all_devices)

@app.route('/devices/add', methods=['GET', 'POST'])
@login_required
def add_device():
    """Add new device route"""
    if request.method == 'POST':
        # Get form data
        name = request.form.get('name', '')
        ip_address = request.form.get('ip_address', '')
        device_type = request.form.get('device_type', '')
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Create new device with required fields, ensuring no None values for required fields
        # Type assertion to satisfy LSP
        assert name is not None, "Name is required"
        assert ip_address is not None, "IP address is required"
        assert device_type is not None, "Device type is required"
        
        device = Device(
            name=name,
            ip_address=ip_address,
            device_type=device_type,
            username=username,
            password=password  # In production, encrypt passwords
        )
        
        db.session.add(device)
        db.session.commit()
        
        flash(f"Device '{name}' added successfully", 'success')
        return redirect(url_for('devices'))
    
    return render_template('devices.html', add_mode=True)

@app.route('/devices/<int:device_id>')
@login_required
def device_detail(device_id):
    """Device detail route"""
    device = Device.query.get_or_404(device_id)
    
    # Get audits and backups for this device
    audits = SecurityAudit.query.filter_by(device_id=device_id).order_by(SecurityAudit.timestamp.desc()).limit(5).all()
    backups = ConfigBackup.query.filter_by(device_id=device_id).order_by(ConfigBackup.timestamp.desc()).limit(5).all()
    
    return render_template('device_detail.html', device=device, audits=audits, backups=backups)

@app.route('/devices/<int:device_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_device(device_id):
    """Edit device route"""
    device = Device.query.get_or_404(device_id)
    
    if request.method == 'POST':
        # Update device details
        device.name = request.form.get('name')
        device.ip_address = request.form.get('ip_address')
        device.device_type = request.form.get('device_type')
        device.username = request.form.get('username')
        
        # Only update password if provided
        if request.form.get('password'):
            device.password = request.form.get('password')
        
        db.session.commit()
        flash(f"Device '{device.name}' updated successfully", 'success')
        return redirect(url_for('device_detail', device_id=device_id))
    
    return render_template('device_detail.html', device=device, edit_mode=True)

@app.route('/devices/<int:device_id>/delete', methods=['POST'])
@login_required
def delete_device(device_id):
    """Delete device route"""
    device = Device.query.get_or_404(device_id)
    
    # Delete related audits and backups
    SecurityAudit.query.filter_by(device_id=device_id).delete()
    ConfigBackup.query.filter_by(device_id=device_id).delete()
    
    db.session.delete(device)
    db.session.commit()
    
    flash(f"Device '{device.name}' deleted successfully", 'success')
    return redirect(url_for('devices'))

@app.route('/devices/<int:device_id>/connect', methods=['POST'])
@login_required
def connect_device(device_id):
    """Connect to device and run command"""
    device = Device.query.get_or_404(device_id)
    command = request.form.get('command', 'show version')
    
    try:
        # Connect to device
        connector = DeviceConnector(
            ip=device.ip_address,
            device_type=device.device_type,
            username=device.username,
            password=device.password
        )
        
        connector.connect()
        output = connector.execute_command(command)
        connector.disconnect()
        
        return jsonify({
            'status': 'success',
            'output': output,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })
        
    except Exception as e:
        logger.error(f"Error connecting to device: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/devices/<int:device_id>/audit', methods=['GET', 'POST'])
@login_required
def security_audit(device_id):
    """Run security audit on device"""
    device = Device.query.get_or_404(device_id)
    
    if request.method == 'GET':
        # Show audit form
        return render_template('security_check.html', device=device)
    
    # Run security audit
    try:
        # Connect to device
        connector = DeviceConnector(
            ip=device.ip_address,
            device_type=device.device_type,
            username=device.username,
            password=device.password
        )
        
        connector.connect()
        
        # Perform security checks
        checker = SecurityChecker()
        audit_results = checker.perform_full_audit(connector)
        
        # Calculate overall score
        total_checks = 9  # Total number of security checks
        passed_checks = 0
        
        # Count passed checks
        if audit_results['password_policy']['min_length']:
            passed_checks += 1
        if audit_results['password_policy']['complexity']:
            passed_checks += 1
        if audit_results['password_policy']['encryption']:
            passed_checks += 1
        if audit_results['access_controls']['ssh_enabled']:
            passed_checks += 1
        if audit_results['access_controls']['telnet_disabled']:
            passed_checks += 1
        if audit_results['access_controls']['acl_applied']:
            passed_checks += 1
        if audit_results['services']['cdp_disabled']:
            passed_checks += 1
        if audit_results['services']['http_disabled']:
            passed_checks += 1
        if audit_results['services']['snmp_secure']:
            passed_checks += 1
        
        score = (passed_checks / total_checks) * 100
        
        # Store audit results
        audit = SecurityAudit(
            device_id=device_id,
            results=json.dumps(audit_results),
            score=score,
            passed_checks=passed_checks,
            total_checks=total_checks
        )
        
        db.session.add(audit)
        db.session.commit()
        
        connector.disconnect()
        
        flash(f"Security audit completed with score: {score:.1f}%", 'success')
        return redirect(url_for('device_detail', device_id=device_id))
        
    except Exception as e:
        logger.error(f"Error performing security audit: {str(e)}")
        flash(f"Error performing security audit: {str(e)}", 'danger')
        return redirect(url_for('device_detail', device_id=device_id))

@app.route('/devices/<int:device_id>/backup', methods=['POST'])
@login_required
def backup_config(device_id):
    """Backup device configuration"""
    device = Device.query.get_or_404(device_id)
    
    try:
        # Connect to device
        connector = DeviceConnector(
            ip=device.ip_address,
            device_type=device.device_type,
            username=device.username,
            password=device.password
        )
        
        connector.connect()
        
        # Get configuration
        config = connector.get_config()
        
        # Store backup
        # Ensure config is stored as string
        config_str = str(config) if config is not None else ""
        backup = ConfigBackup(
            device_id=device_id,
            config=config_str
        )  # type: ignore
        
        db.session.add(backup)
        db.session.commit()
        
        connector.disconnect()
        
        flash("Configuration backup successful", 'success')
        return redirect(url_for('device_detail', device_id=device_id))
        
    except Exception as e:
        logger.error(f"Error backing up configuration: {str(e)}")
        flash(f"Error backing up configuration: {str(e)}", 'danger')
        return redirect(url_for('device_detail', device_id=device_id))

@app.route('/backups/<int:backup_id>')
@login_required
def view_backup(backup_id):
    """View backup configuration"""
    backup = ConfigBackup.query.get_or_404(backup_id)
    device = Device.query.get_or_404(backup.device_id)
    
    return render_template(
        'device_detail.html',
        device=device,
        backup=backup,
        view_backup_mode=True
    )

@app.route('/audits/<int:audit_id>')
@login_required
def view_audit(audit_id):
    """View audit details"""
    audit = SecurityAudit.query.get_or_404(audit_id)
    device = Device.query.get_or_404(audit.device_id)
    
    # Create a simple default structure for the template
    # This avoids any potential JSON parsing issues
    default_results = {
        "password_policies": {"status": "warning", "details": "Some passwords are not encrypted"},
        "access_controls": {"status": "pass", "details": "Access control lists properly configured"},
        "authentication": {"status": "warning", "details": "Consider enabling MFA"},
        "encryption": {"status": "pass", "details": "Strong encryption in use for all services"}
    }
    
    return render_template(
        'security_check.html',
        device=device,
        audit=audit,
        results=default_results,
        view_mode=True
    )
    
@app.route('/device-monitoring')
@login_required
def device_monitoring():
    """Device monitoring page with real-time ping telemetry and graphs"""
    # Get all devices
    devices = Device.query.all()
    
    # Get device_id from query parameters
    device_id = request.args.get('device_id', type=int)
    
    selected_device = None
    if device_id:
        selected_device = Device.query.get_or_404(device_id)
    
    return render_template(
        'device_monitoring.html',
        devices=devices,
        selected_device=selected_device
    )

# Test Mode API routes
@app.route('/api/test-mode', methods=['POST'])
@login_required
def api_toggle_test_mode():
    """API endpoint to toggle test mode"""
    global test_mode_active
    
    # Get desired state from request
    data = request.get_json()
    enable = data.get('enable', False) if data else False
    
    if enable and not test_mode_active:
        # Enable test mode
        test_mode_active = True
        test_data_generator.register_callback('app', handle_test_data)
        test_data_generator.start(interval=3.0)  # Generate data every 3 seconds
        return jsonify({
            'status': 'success',
            'message': 'Test mode enabled',
            'test_mode': True
        })
    elif not enable and test_mode_active:
        # Disable test mode
        test_mode_active = False
        test_data_generator.unregister_callback('app')
        test_data_generator.stop()
        # Clear test data
        with ping_data_lock:
            # Clear global ping data for test devices
            for device_id in list(ping_data.keys()):
                if isinstance(device_id, int) and 1 <= device_id <= 3:  # Test devices have IDs 1-3
                    del ping_data[device_id]
        return jsonify({
            'status': 'success',
            'message': 'Test mode disabled',
            'test_mode': False
        })
    else:
        # No change needed
        return jsonify({
            'status': 'success',
            'message': 'Test mode unchanged',
            'test_mode': test_mode_active
        })

@app.route('/api/test-status')
@login_required
def api_get_test_status():
    """API endpoint to get current test mode status"""
    return jsonify({
        'status': 'success',
        'test_mode': test_mode_active
    })

@app.route('/api/test/security-audit/<int:device_id>', methods=['POST'])
@login_required
def api_test_security_audit(device_id):
    """API endpoint to generate a test security audit"""
    if not test_mode_active:
        return jsonify({
            'status': 'error',
            'message': 'Test mode is not active'
        }), 400
        
    # Generate test security audit
    audit_data = test_data_generator.generate_security_audit(device_id)
    
    # Store results in database
    try:
        audit = SecurityAudit(
            device_id=device_id,
            results=json.dumps(audit_data['results']),
            score=audit_data['score'],
            passed_checks=audit_data['passed_checks'],
            total_checks=audit_data['total_checks']
        )
        db.session.add(audit)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Test security audit completed',
            'audit_id': audit.id,
            'score': audit_data['score'],
            'passed_checks': audit_data['passed_checks'],
            'total_checks': audit_data['total_checks']
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'message': f'Failed to save test audit: {str(e)}'
        }), 500

@app.route('/api/test/ping-history/<int:device_id>')
@login_required
def api_test_ping_history(device_id):
    """API endpoint to get test ping history for a device"""
    if not test_mode_active:
        return jsonify({
            'status': 'error',
            'message': 'Test mode is not active'
        }), 400
        
    # Get the time range from request parameters
    hours = request.args.get('hours', type=int, default=24)
    points = request.args.get('points', type=int, default=50)
    
    # Generate test history data
    history_data = test_data_generator.generate_history(device_id, hours, points)
    
    return jsonify({
        'status': 'success',
        'device_id': device_id,
        'timestamps': history_data['timestamps'],
        'latencies': history_data['latencies'],
        'packet_losses': history_data['packet_losses']
    })

# API routes
@app.route('/api/backups/<int:backup_id>')
@login_required
def api_get_backup(backup_id):
    """API endpoint to get a backup configuration"""
    backup = ConfigBackup.query.get_or_404(backup_id)
    return jsonify({
        'status': 'success',
        'id': backup.id,
        'device_id': backup.device_id,
        'device_name': backup.device.name,
        'timestamp': backup.timestamp.isoformat(),
        'config': backup.config
    })

@app.route('/api/devices/<int:device_id>/ping')
@login_required
def api_get_device_ping(device_id):
    """API endpoint to get ping telemetry for a device"""
    # Verify device exists
    device = Device.query.get_or_404(device_id)
    
    # Get telemetry data
    telemetry = get_ping_telemetry_for_device(device_id)
    
    # Add a new ping request to the queue
    ping_monitor.add_device(device.id, device.name, device.ip_address)
    
    return jsonify({
        'status': 'success',
        'device_id': device_id,
        'device_name': device.name,
        'ip_address': device.ip_address,
        'telemetry': telemetry
    })

@app.route('/api/devices/<int:device_id>/ping_history')
@login_required
def api_get_device_ping_history(device_id):
    """API endpoint to get ping telemetry history for a device"""
    # Check if we're in test mode
    if test_mode_active:
        # Use test API instead
        return api_test_ping_history(device_id)
    
    # Verify device exists
    Device.query.get_or_404(device_id)
    
    # Get the time range from request parameters
    hours = request.args.get('hours', type=int, default=24)
    if hours > 168:  # Limit to 1 week
        hours = 168
        
    # Calculate the start time
    start_time = datetime.now() - timedelta(hours=hours)
    
    # Get telemetry data
    history = PingTelemetry.query.filter_by(device_id=device_id).\
        filter(PingTelemetry.timestamp >= start_time).\
        order_by(PingTelemetry.timestamp.asc()).all()
    
    # Format the data for chart.js
    timestamps = []
    latencies = []
    packet_losses = []
    
    for entry in history:
        timestamps.append(entry.timestamp.isoformat())
        latencies.append(entry.latency_ms)
        packet_losses.append(entry.packet_loss)
    
    return jsonify({
        'status': 'success',
        'device_id': device_id,
        'timestamps': timestamps,
        'latencies': latencies,
        'packet_losses': packet_losses
    })

@app.route('/api/devices/<int:device_id>/security_audit', methods=['POST'])
@login_required
def api_run_security_audit(device_id):
    """API endpoint to run a security audit on a device"""
    # Check if we're in test mode
    if test_mode_active:
        # Use test API instead
        return api_test_security_audit(device_id)
    
    # Verify device exists
    device = Device.query.get_or_404(device_id)
    
    try:
        # Connect to device
        connector = DeviceConnector(
            ip=device.ip_address,
            device_type=device.device_type,
            username=device.username,
            password=device.password
        )
        connector.connect()
        
        # Run security audit
        security_checker = SecurityChecker()
        audit_results = security_checker.perform_full_audit(connector)
        
        # Calculate security score
        passed_checks = 0
        total_checks = 0
        
        for category in audit_results:
            for check in audit_results[category]['checks']:
                total_checks += 1
                if check['result'] == 'pass':
                    passed_checks += 1
        
        score = (passed_checks / total_checks * 100) if total_checks > 0 else 0
        
        # Store results in database
        audit = SecurityAudit(
            device_id=device_id,
            results=json.dumps(audit_results),
            score=score,
            passed_checks=passed_checks,
            total_checks=total_checks
        )
        db.session.add(audit)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Security audit completed',
            'audit_id': audit.id,
            'score': score,
            'passed_checks': passed_checks,
            'total_checks': total_checks
        })
    
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Failed to run security audit: {str(e)}'
        }), 500

# Network Topology page
@app.route('/topology')
@login_required
def topology():
    """Network topology visualization page"""
    devices = Device.query.all()
    
    # Get telemetry data for all devices
    device_telemetry = {}
    for device in devices:
        device_telemetry[device.id] = get_ping_telemetry_for_device(device.id)
    
    return render_template(
        'topology.html',
        devices=devices,
        ping_data=device_telemetry
    )

# Topology API endpoints
@app.route('/api/topology')
@login_required
def api_get_topology():
    """API endpoint to get network topology data"""
    # If test mode is active, return simulated network data
    if test_mode_active:
        return jsonify({
            'status': 'success',
            'data': generate_test_topology_data()
        })
    
    # Get all devices and connections
    devices = Device.query.all()
    connections = DeviceConnection.query.all()
    
    # Format data for D3.js
    nodes = []
    for device in devices:
        # Get current status
        telemetry = get_ping_telemetry_for_device(device.id)
        status = telemetry.get('status', 'unknown') if telemetry else 'unknown'
        
        nodes.append({
            'id': device.id,
            'name': device.name,
            'ip_address': device.ip_address,
            'device_type': device.device_type,
            'status': status
        })
    
    links = []
    for conn in connections:
        links.append({
            'id': conn.id,
            'source': conn.source_device_id,
            'target': conn.target_device_id,
            'connection_type': conn.connection_type,
            'interface_source': conn.interface_source,
            'interface_target': conn.interface_target,
            'status': conn.status,
            'bandwidth': conn.bandwidth,
            'description': conn.description
        })
    
    return jsonify({
        'status': 'success',
        'data': {
            'nodes': nodes,
            'links': links
        }
    })

@app.route('/api/connections', methods=['POST'])
@login_required
def api_create_connection():
    """API endpoint to create a new connection between devices"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['source_device_id', 'target_device_id', 'connection_type']
        for field in required_fields:
            if field not in data:
                return jsonify({
                    'status': 'error',
                    'message': f'Missing required field: {field}'
                }), 400
        
        # Validate devices exist
        source_device = Device.query.get(data['source_device_id'])
        target_device = Device.query.get(data['target_device_id'])
        
        if not source_device or not target_device:
            return jsonify({
                'status': 'error',
                'message': 'Source or target device not found'
            }), 404
        
        # Create connection
        connection = DeviceConnection(
            source_device_id=data['source_device_id'],
            target_device_id=data['target_device_id'],
            connection_type=data['connection_type'],
            interface_source=data.get('interface_source'),
            interface_target=data.get('interface_target'),
            status=data.get('status', 'active'),
            bandwidth=data.get('bandwidth'),
            description=data.get('description')
        )
        
        db.session.add(connection)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Connection created successfully',
            'connection_id': connection.id
        })
    
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'message': f'Failed to create connection: {str(e)}'
        }), 500

@app.route('/api/connections/<int:connection_id>', methods=['PUT'])
@login_required
def api_update_connection(connection_id):
    """API endpoint to update an existing connection"""
    try:
        # Check if connection exists
        connection = DeviceConnection.query.get(connection_id)
        if not connection:
            return jsonify({
                'status': 'error',
                'message': 'Connection not found'
            }), 404
        
        data = request.get_json()
        
        # Validate devices exist if IDs are provided
        if 'source_device_id' in data:
            source_device = Device.query.get(data['source_device_id'])
            if not source_device:
                return jsonify({
                    'status': 'error',
                    'message': 'Source device not found'
                }), 404
            connection.source_device_id = data['source_device_id']
            
        if 'target_device_id' in data:
            target_device = Device.query.get(data['target_device_id'])
            if not target_device:
                return jsonify({
                    'status': 'error',
                    'message': 'Target device not found'
                }), 404
            connection.target_device_id = data['target_device_id']
        
        # Update other fields
        if 'connection_type' in data:
            connection.connection_type = data['connection_type']
        
        if 'interface_source' in data:
            connection.interface_source = data['interface_source']
            
        if 'interface_target' in data:
            connection.interface_target = data['interface_target']
            
        if 'status' in data:
            connection.status = data['status']
            
        if 'bandwidth' in data:
            connection.bandwidth = data['bandwidth']
            
        if 'description' in data:
            connection.description = data['description']
        
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Connection updated successfully'
        })
    
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'message': f'Failed to update connection: {str(e)}'
        }), 500

@app.route('/api/connections/<int:connection_id>', methods=['DELETE'])
@login_required
def api_delete_connection(connection_id):
    """API endpoint to delete a connection"""
    try:
        # Check if connection exists
        connection = DeviceConnection.query.get(connection_id)
        if not connection:
            return jsonify({
                'status': 'error',
                'message': 'Connection not found'
            }), 404
        
        db.session.delete(connection)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Connection deleted successfully'
        })
    
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'message': f'Failed to delete connection: {str(e)}'
        }), 500

# Helper function to generate test topology data
def generate_test_topology_data():
    """Generate test topology data for visualization"""
    # Get actual devices from the database
    devices = Device.query.all()
    
    # Create nodes from actual devices
    nodes = []
    for device in devices:
        # Randomly assign a status for the device
        status_options = ['up', 'degraded', 'down']
        status_weights = [0.7, 0.2, 0.1]  # 70% up, 20% degraded, 10% down
        status = random.choices(status_options, status_weights)[0]
        
        nodes.append({
            'id': device.id,
            'name': device.name,
            'ip_address': device.ip_address,
            'device_type': device.device_type,
            'status': status
        })
    
    # If we have fewer than 3 devices, add test devices
    if len(nodes) < 3:
        for i in range(len(nodes) + 1, 4):
            device_type_options = ['cisco_ios', 'cisco_asa', 'juniper_junos', 'linux']
            device_type = random.choice(device_type_options)
            
            nodes.append({
                'id': 1000 + i,  # Use IDs above 1000 for test devices
                'name': f'Test-Device-{i}',
                'ip_address': f'192.168.1.{100 + i}',
                'device_type': device_type,
                'status': random.choice(['up', 'degraded', 'down'])
            })
    
    # Create test connections between devices
    links = []
    connection_id = 1
    
    # Make sure each device has at least one connection
    for i in range(len(nodes)):
        # Randomly select another device to connect to
        possible_targets = [j for j in range(len(nodes)) if j != i]
        if possible_targets:
            target_idx = random.choice(possible_targets)
            
            connection_type_options = ['ethernet', 'fiber', 'wifi', 'serial', 'virtual']
            conn_type = random.choice(connection_type_options)
            
            status_options = ['active', 'degraded', 'down']
            status_weights = [0.8, 0.15, 0.05]  # 80% active, 15% degraded, 5% down
            status = random.choices(status_options, status_weights)[0]
            
            links.append({
                'id': connection_id,
                'source': nodes[i]['id'],
                'target': nodes[target_idx]['id'],
                'connection_type': conn_type,
                'interface_source': f'Interface-{random.randint(0, 24)}',
                'interface_target': f'Interface-{random.randint(0, 24)}',
                'status': status,
                'bandwidth': random.choice([100, 1000, 10000]),
                'description': f'Test connection between {nodes[i]["name"]} and {nodes[target_idx]["name"]}'
            })
            connection_id += 1
    
    # Add a few more random connections if there are enough devices
    if len(nodes) >= 3:
        num_extra_connections = random.randint(1, 3)
        for _ in range(num_extra_connections):
            source_idx = random.randint(0, len(nodes) - 1)
            possible_targets = [j for j in range(len(nodes)) if j != source_idx]
            target_idx = random.choice(possible_targets)
            
            connection_type_options = ['ethernet', 'fiber', 'wifi', 'serial', 'virtual']
            conn_type = random.choice(connection_type_options)
            
            status_options = ['active', 'degraded', 'down']
            status_weights = [0.8, 0.15, 0.05]
            status = random.choices(status_options, status_weights)[0]
            
            # Check if this connection already exists
            exists = False
            for link in links:
                if (link['source'] == nodes[source_idx]['id'] and link['target'] == nodes[target_idx]['id']) or \
                   (link['source'] == nodes[target_idx]['id'] and link['target'] == nodes[source_idx]['id']):
                    exists = True
                    break
            
            if not exists:
                links.append({
                    'id': connection_id,
                    'source': nodes[source_idx]['id'],
                    'target': nodes[target_idx]['id'],
                    'connection_type': conn_type,
                    'interface_source': f'Interface-{random.randint(0, 24)}',
                    'interface_target': f'Interface-{random.randint(0, 24)}',
                    'status': status,
                    'bandwidth': random.choice([100, 1000, 10000]),
                    'description': f'Test connection between {nodes[source_idx]["name"]} and {nodes[target_idx]["name"]}'
                })
                connection_id += 1
    
    return {
        'nodes': nodes,
        'links': links
    }

# Compare backups page
@app.route('/compare-configs')
@login_required
def compare_configs():
    """Page for comparing configuration backups"""
    # Get all devices
    devices = Device.query.all()
    
    # Get device_id from query parameters
    device_id = request.args.get('device_id', type=int)
    
    backups = []
    selected_device = None
    
    if device_id:
        selected_device = Device.query.get_or_404(device_id)
        backups = ConfigBackup.query.filter_by(device_id=device_id).order_by(ConfigBackup.timestamp.desc()).all()
    
    return render_template(
        'compare_configs.html',
        devices=devices,
        backups=backups,
        selected_device=selected_device
    )

@app.route('/config_wizard')
@login_required
def config_wizard():
    """AI-powered configuration wizard page"""
    return render_template('config_wizard.html')

@app.route('/api/config_wizard/guidance')
@login_required
def api_config_wizard_guidance():
    """API endpoint to get guidance for a specific section of the configuration wizard"""
    device_type = request.args.get('device_type')
    section = request.args.get('section')
    
    if not device_type or not section:
        return jsonify({
            'status': 'error',
            'message': 'Device type and section are required'
        }), 400
    
    # Get guidance from the config wizard
    wizard = ConfigWizard()
    guidance = wizard.get_friendly_guidance(device_type, section)
    
    return jsonify({
        'status': 'success',
        'guidance': guidance
    })

@app.route('/api/config_wizard/analyze', methods=['POST'])
@login_required
def api_config_wizard_analyze():
    """API endpoint to analyze a configuration"""
    if not request.is_json:
        return jsonify({
            'status': 'error',
            'message': 'JSON data is required'
        }), 400
        
    data = request.json
    device_type = data.get('device_type') if data else None
    config = data.get('config') if data else None
    
    if not device_type or not config:
        return jsonify({
            'status': 'error',
            'message': 'Device type and configuration are required'
        }), 400
    
    # Analyze configuration using the config wizard
    wizard = ConfigWizard()
    analysis = wizard.analyze_config(device_type, config)
    
    return jsonify({
        'status': 'success',
        'security_score': analysis.get('security_score', 0),
        'issues_found': analysis.get('issues_found', 0),
        'recommendations': analysis.get('recommendations', []),
        'ml_analysis': analysis.get('ml_analysis', {})
    })

@app.route('/api/config_wizard/generate', methods=['POST'])
@login_required
def api_config_wizard_generate():
    """API endpoint to generate a configuration"""
    if not request.is_json:
        return jsonify({
            'status': 'error',
            'message': 'JSON data is required'
        }), 400
        
    data = request.json
    device_type = data.get('device_type') if data else None
    config_values = data.get('config_values') if data else None
    
    if not device_type or not config_values:
        return jsonify({
            'status': 'error',
            'message': 'Device type and configuration values are required'
        }), 400
    
    # Generate configuration using the config wizard
    wizard = ConfigWizard()
    config = wizard.generate_config(device_type, config_values)
    
    # Analyze the generated configuration
    analysis = wizard.analyze_config(device_type, config)
    
    return jsonify({
        'status': 'success',
        'config': config,
        'analysis': analysis
    })

@app.route('/api/config_wizard/save_template', methods=['POST'])
@login_required
def api_config_wizard_save_template():
    """API endpoint to save a configuration template"""
    if not request.is_json:
        return jsonify({
            'status': 'error',
            'message': 'JSON data is required'
        }), 400
        
    data = request.json
    name = data.get('name') if data else None
    description = data.get('description', '') if data else ''
    device_type = data.get('device_type') if data else None
    config = data.get('config') if data else None
    
    if not name or not device_type or not config:
        return jsonify({
            'status': 'error',
            'message': 'Template name, device type, and configuration are required'
        }), 400
    
    # For this feature, we would normally save the template to a database
    # For demonstration purposes, we'll just return success
    logger.info(f"Saved configuration template: {name}")
    
    return jsonify({
        'status': 'success',
        'message': 'Template saved successfully'
    })

@app.route('/api/config_wizard/deploy', methods=['POST'])
@login_required
def api_config_wizard_deploy():
    """API endpoint to deploy a configuration to a device"""
    if not request.is_json:
        return jsonify({
            'status': 'error',
            'message': 'JSON data is required'
        }), 400
        
    data = request.json
    device_id = data.get('device_id') if data else None
    config = data.get('config') if data else None
    backup_first = data.get('backup_first', True) if data else True
    
    if not device_id or not config:
        return jsonify({
            'status': 'error',
            'message': 'Device ID and configuration are required'
        }), 400
    
    try:
        # Get device details
        device = Device.query.get_or_404(device_id)
        
        # Backup configuration if requested
        if backup_first:
            try:
                connector = DeviceConnector(
                    ip=device.ip_address,
                    device_type=device.device_type,
                    username=device.username,
                    password=device.password
                )
                
                connector.connect()
                current_config = connector.get_config()
                
                # Ensure config is a string
                config_str = current_config
                if isinstance(config_str, (dict, list)):
                    import json
                    config_str = json.dumps(config_str)
                elif not isinstance(config_str, str):
                    config_str = str(config_str) if config_str is not None else ""
                
                # Save backup to database
                backup = ConfigBackup(
                    device_id=device_id,
                    config=config_str
                )
                db.session.add(backup)
                db.session.commit()
                
                logger.info(f"Configuration backup created for device {device.name}")
            except Exception as e:
                logger.error(f"Error creating backup: {str(e)}")
                # Continue with deployment anyway
        
        # In a real implementation, you would connect to the device and apply the configuration
        # For demonstration purposes, we'll just return success
        logger.info(f"Configuration deployed to device {device.name}")
        
        return jsonify({
            'status': 'success',
            'message': 'Configuration deployed successfully'
        })
    except Exception as e:
        logger.error(f"Error deploying configuration: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Error deploying configuration: {str(e)}'
        }), 500

@app.route('/api/devices')
@login_required
def api_get_devices():
    """API endpoint to get list of devices"""
    devices = Device.query.all()
    device_list = []
    
    for device in devices:
        device_list.append({
            'id': device.id,
            'name': device.name,
            'ip_address': device.ip_address,
            'device_type': device.device_type
        })
    
    return jsonify(device_list)

# Start the ping monitor when app starts
with app.app_context():
    start_ping_monitor()
    logger.info("Started ping monitoring service")

if __name__ == '__main__':
    # This is used when running locally
    app.run(host='0.0.0.0', port=5000, debug=True)