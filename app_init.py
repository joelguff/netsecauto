"""
Initialize Flask app and database
"""
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from sqlalchemy.orm import DeclarativeBase
import os
import logging

# Setup logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Initialize Flask app
class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)
app = Flask(__name__)

# Set secret key
app.secret_key = os.environ.get("SESSION_SECRET", "development_secret_key")

# Configure session to work with Flask 3.x and Werkzeug compatibility issues
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Import and use our custom session interface to handle compatibility issues
try:
    from utils.session_compat import CompatibleSessionInterface
    logger.info("Using custom compatible session interface")
    app.session_interface = CompatibleSessionInterface()
except ImportError:
    logger.warning("Failed to import custom session interface, using default")

# Database configuration
database_url = os.environ.get("DATABASE_URL")
if database_url:
    app.config["SQLALCHEMY_DATABASE_URI"] = database_url
else:
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///netsec.db"

app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}

# Initialize extensions
db.init_app(app)

# Setup Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    from models import User
    # Try both int and string user_id to handle different ID types
    try:
        # First try as integer (for the demo admin user)
        return User.query.get(int(user_id))
    except ValueError:
        # If that fails, try as string (for OAuth users)
        return User.query.get(user_id)