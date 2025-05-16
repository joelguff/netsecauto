# Database models for Network Security Tool
from datetime import datetime
from typing import Optional, List
from app_init import db
from flask_login import UserMixin
from sqlalchemy.orm import Mapped, relationship
from sqlalchemy import String, Integer, Float, DateTime, Text, ForeignKey

class User(UserMixin, db.Model):
    __tablename__ = 'user'
    
    id: Mapped[int] = db.Column(db.Integer, primary_key=True)
    username: Mapped[str] = db.Column(db.String(64), unique=True, nullable=False)
    email: Mapped[str] = db.Column(db.String(120), unique=True, nullable=False)
    password_hash: Mapped[str] = db.Column(db.String(256), nullable=False)
    created_at: Mapped[datetime] = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __init__(self, username: str, email: str, password_hash: str):
        self.username = username
        self.email = email
        self.password_hash = password_hash
    
    def __repr__(self):
        return f'<User {self.username}>'

class Device(db.Model):
    __tablename__ = 'device'
    
    id: Mapped[int] = db.Column(db.Integer, primary_key=True)
    name: Mapped[str] = db.Column(db.String(64), nullable=False)
    ip_address: Mapped[str] = db.Column(db.String(64), nullable=False)
    device_type: Mapped[str] = db.Column(db.String(32), nullable=False)
    username: Mapped[Optional[str]] = db.Column(db.String(64))
    password: Mapped[Optional[str]] = db.Column(db.String(128))  # In production, encrypt passwords
    created_at: Mapped[datetime] = db.Column(db.DateTime, default=datetime.utcnow)
    last_connected: Mapped[Optional[datetime]] = db.Column(db.DateTime)
    
    # Relationships
    audits: Mapped[List["SecurityAudit"]] = relationship('SecurityAudit', backref='device', lazy=True)
    backups: Mapped[List["ConfigBackup"]] = relationship('ConfigBackup', backref='device', lazy=True)
    # 'ping_telemetry' relationship is added later
    
    def __init__(self, name: str, ip_address: str, device_type: str, username: Optional[str] = None, password: Optional[str] = None):
        self.name = name
        self.ip_address = ip_address
        self.device_type = device_type
        self.username = username
        self.password = password
    
    def __repr__(self):
        return f'<Device {self.name} ({self.ip_address})>'

class SecurityAudit(db.Model):
    __tablename__ = 'security_audit'
    
    id: Mapped[int] = db.Column(db.Integer, primary_key=True)
    device_id: Mapped[int] = db.Column(db.Integer, db.ForeignKey('device.id'), nullable=False)
    timestamp: Mapped[datetime] = db.Column(db.DateTime, default=datetime.utcnow)
    results: Mapped[str] = db.Column(db.Text, nullable=False)  # JSON string of audit results
    score: Mapped[Optional[float]] = db.Column(db.Float)  # Security score (percentage)
    passed_checks: Mapped[Optional[int]] = db.Column(db.Integer)
    total_checks: Mapped[Optional[int]] = db.Column(db.Integer)
    
    def __init__(self, device_id: int, results: str, score: Optional[float] = None, 
                 passed_checks: Optional[int] = None, total_checks: Optional[int] = None):
        self.device_id = device_id
        self.results = results
        self.score = score
        self.passed_checks = passed_checks
        self.total_checks = total_checks
    
    def __repr__(self):
        return f'<Audit {self.id} for Device {self.device_id}>'

class ConfigBackup(db.Model):
    __tablename__ = 'config_backup'
    
    id: Mapped[int] = db.Column(db.Integer, primary_key=True)
    device_id: Mapped[int] = db.Column(db.Integer, db.ForeignKey('device.id'), nullable=False)
    timestamp: Mapped[datetime] = db.Column(db.DateTime, default=datetime.utcnow)
    config: Mapped[str] = db.Column(db.Text, nullable=False)
    
    def __init__(self, device_id: int, config: str):
        self.device_id = device_id
        self.config = config
    
    def __repr__(self):
        return f'<Backup {self.id} for Device {self.device_id}>'

class PingTelemetry(db.Model):
    __tablename__ = 'ping_telemetry'
    
    id: Mapped[int] = db.Column(db.Integer, primary_key=True)
    device_id: Mapped[int] = db.Column(db.Integer, db.ForeignKey('device.id'), nullable=False)
    timestamp: Mapped[datetime] = db.Column(db.DateTime, default=datetime.utcnow)
    latency_ms: Mapped[float] = db.Column(db.Float)  # Ping latency in milliseconds
    packet_loss: Mapped[float] = db.Column(db.Float)  # Packet loss percentage
    status: Mapped[str] = db.Column(db.String(20))  # Status: 'up', 'down', 'degraded'
    
    def __init__(self, device_id: int, latency_ms: float, packet_loss: float, status: str):
        self.device_id = device_id
        self.latency_ms = latency_ms
        self.packet_loss = packet_loss
        self.status = status
        
    def __repr__(self):
        return f'<PingTelemetry {self.id} for Device {self.device_id}: {self.latency_ms}ms, {self.packet_loss}% loss>'

class DeviceConnection(db.Model):
    __tablename__ = 'device_connection'
    
    id: Mapped[int] = db.Column(db.Integer, primary_key=True)
    source_device_id: Mapped[int] = db.Column(db.Integer, db.ForeignKey('device.id'), nullable=False)
    target_device_id: Mapped[int] = db.Column(db.Integer, db.ForeignKey('device.id'), nullable=False)
    connection_type: Mapped[str] = db.Column(db.String(50))  # e.g., 'ethernet', 'wifi', 'serial', etc.
    interface_source: Mapped[Optional[str]] = db.Column(db.String(50))  # e.g., 'GigabitEthernet0/1'
    interface_target: Mapped[Optional[str]] = db.Column(db.String(50))  # e.g., 'GigabitEthernet0/2'
    status: Mapped[str] = db.Column(db.String(20), default='active')  # Status: 'active', 'down', 'degraded'
    bandwidth: Mapped[Optional[int]] = db.Column(db.Integer)  # Bandwidth in Mbps
    description: Mapped[Optional[str]] = db.Column(db.String(200))
    created_at: Mapped[datetime] = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    source_device: Mapped["Device"] = relationship('Device', foreign_keys=[source_device_id], backref='outgoing_connections')
    target_device: Mapped["Device"] = relationship('Device', foreign_keys=[target_device_id], backref='incoming_connections')
    
    def __init__(self, source_device_id: int, target_device_id: int, connection_type: str,
                 interface_source: Optional[str] = None, interface_target: Optional[str] = None,
                 status: str = 'active', bandwidth: Optional[int] = None, description: Optional[str] = None):
        self.source_device_id = source_device_id
        self.target_device_id = target_device_id
        self.connection_type = connection_type
        self.interface_source = interface_source
        self.interface_target = interface_target
        self.status = status
        self.bandwidth = bandwidth
        self.description = description
        
    def __repr__(self):
        return f'<DeviceConnection {self.id}: {self.source_device_id} → {self.target_device_id}>'
