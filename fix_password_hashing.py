#!/usr/bin/env python3
"""
Password Hash Fix Script

This script fixes the password hashing issue by:
1. Dropping the existing user table
2. Recreating it with proper password hashing
3. Creating fresh user accounts with compatible hash format

Author: Joel Aaron Guff
"""

import os
import logging
from datetime import datetime
from werkzeug.security import generate_password_hash
from app_init import app, db
from models import User

# Configure logging
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def fix_password_hashing():
    """Fix password hashing by recreating the user table and adding users with proper hashing"""
    with app.app_context():
        try:
            # Drop and recreate the user table
            logger.info("Dropping user table...")
            User.__table__.drop(db.engine, checkfirst=True)
            db.create_all()
            logger.info("User table recreated successfully")
            
            # Create admin user with proper password hashing
            logger.info("Creating admin user...")
            admin = User(
                username='admin',
                email='admin@example.com',
                password_hash=generate_password_hash('admin', method='pbkdf2:sha256', salt_length=16)
            )
            db.session.add(admin)
            
            # Create demo user with proper password hashing
            logger.info("Creating demo user...")
            demo = User(
                username='demo',
                email='demo@example.com',
                password_hash=generate_password_hash('demo123', method='pbkdf2:sha256', salt_length=16)
            )
            db.session.add(demo)
            
            db.session.commit()
            logger.info("User accounts created successfully with compatible password hashing")
            logger.info("Demo user credentials: demo / demo123")
            
            return True
        except Exception as e:
            logger.error(f"Error fixing password hashing: {e}")
            return False

if __name__ == "__main__":
    logger.info("Starting password hash fix...")
    if fix_password_hashing():
        logger.info("Password hashing fix completed successfully")
    else:
        logger.error("Failed to fix password hashing")