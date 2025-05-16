"""
WSGI entry point for the application
Author: Joel Aaron Guff

This file serves as the WSGI entry point for the application when running in production environments.
It provides the 'app' object that WSGI servers like Gunicorn can use to handle HTTP requests.
"""
import logging
from app import app
import routes  # Import all routes

# Configure logging
logging.basicConfig(level=logging.INFO)
logging.info("Starting Network Security Automation Tool via WSGI")

# This is the WSGI application object that will be used by gunicorn
application = app

if __name__ == "__main__":
    # If we run this file directly, we'll start the development server
    app.run(host="0.0.0.0", port=5000, debug=True)