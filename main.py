# main.py
from flask import Flask
from flask_cors import CORS
import os
import logging
from datetime import datetime, timezone
from config import SECRET_KEY

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Application start time for uptime calculations
app_start_time = datetime.now(timezone.utc)

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Secret key for JWT
app.config['SECRET_KEY'] = SECRET_KEY

# Import and initialize database first
from utils import init_db_pool, init_db

# Initialize the database when the app starts
with app.app_context():
    init_db_pool()
    init_db()

# Import blueprints AFTER app creation
from admin import admin_bp
from vendors import vendors_bp
from mobile_vendors import mobile_vendors_bp
from officers import officers_bp
from shared import shared_bp

# Register blueprints
app.register_blueprint(admin_bp, url_prefix='/api/admin')
app.register_blueprint(vendors_bp, url_prefix='/api/vendor')
app.register_blueprint(mobile_vendors_bp, url_prefix='/api/mobile')
app.register_blueprint(officers_bp, url_prefix='/api/officers')
app.register_blueprint(shared_bp, url_prefix='/api')

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)