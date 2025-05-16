#!/bin/bash
# Start the Network Security Automation Tool in production mode
# Author: Joel Aaron Guff

# Initialize the database if needed
echo "Setting up environment..."
python rebuild_database.py

# Start with Gunicorn
echo "Starting production server with Gunicorn..."
gunicorn --bind 0.0.0.0:8080 wsgi:app