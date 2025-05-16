#!/usr/bin/env python3
"""
Network Security Automation Tool - Main Application Entry Point
Author: Joel Aaron Guff

This script provides a simple entry point to start the web application.
It imports the Flask app from app.py and starts the server with debug mode enabled.
"""
import logging
import sys
import traceback

# Configure logging
logging.basicConfig(level=logging.DEBUG, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
logger.info("Starting Network Security Automation Tool")

try:
    from app import app
    import routes  # Import all routes
    logger.info("Successfully imported application modules")
except Exception as e:
    logger.error(f"Error importing application modules: {e}")
    traceback.print_exc()
    sys.exit(1)

if __name__ == "__main__":
    try:
        # Start the Flask web server on port 8080 with access from any host
        logger.info("Starting web server on port 8080")
        app.run(host="0.0.0.0", port=8080, debug=True)
    except Exception as e:
        logger.error(f"Error starting web server: {e}")
        traceback.print_exc()
        sys.exit(1)