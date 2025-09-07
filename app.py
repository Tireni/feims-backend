from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import mysql.connector
import uuid
from datetime import datetime, timedelta, timezone
import bcrypt
import jwt
import os
from werkzeug.utils import secure_filename
from functools import wraps
import qrcode
import io
import base64
import json
import time
import logging
import re

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# -----------------------------------------------------------------------------
# Application start time for uptime calculations
app_start_time = datetime.now(timezone.utc)

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Secret key for JWT
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'feims-secret-key-2025'

# -----------------------------------------------------------------------------
# Admin configuration
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'adminpass')

def admin_token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization')
        if auth_header:
            parts = auth_header.split()
            if len(parts) == 2 and parts[0].lower() == 'bearer':
                token = parts[1]
        if not token:
            return jsonify({'success': False, 'message': 'Admin token is missing'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            if data.get('role') != 'admin':
                return jsonify({'success': False, 'message': 'Admin privileges required'}), 403
            current_admin = {'username': data.get('username')}
        except Exception as e:
            logger.error(f"Admin token validation error: {e}")
            return jsonify({'success': False, 'message': 'Invalid or expired admin token'}), 401
        return f(current_admin, *args, **kwargs)
    return decorated

# -----------------------------------------------------------------------------
# File upload configuration
UPLOAD_FOLDER = 'uploads/decommissions'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Create upload directory safely
try:
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
except Exception as e:
    logger.warning(f"Could not create upload directory: {e}")

def allowed_file(filename: str) -> bool:
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Database configuration - use environment variables
db_config = {
    'host': os.environ.get('MYSQLHOST', '95.85.5.9'),
    'user': os.environ.get('MYSQLUSER', 'ffsnfdrcnet_enoch'),
    'password': os.environ.get('MYSQLPASSWORD', 'Enoch@0330'),
    'database': os.environ.get('MYSQLDATABASE', 'ffsnfdrcnet_feimsdb'),
    'port': int(os.environ.get('MYSQLPORT', 3306)),
    'connect_timeout': 30,
    'autocommit': True,
    'pool_name': 'feims_pool',
    'pool_size': 5,
    'pool_reset_session': True
}

# Database connection pool
db_pool = None

def init_db_pool():
    """Initialize database connection pool"""
    global db_pool
    try:
        db_pool = mysql.connector.pooling.MySQLConnectionPool(**db_config)
        logger.info("Database connection pool created successfully")
        return True
    except Exception as e:
        logger.error(f"Failed to create database connection pool: {e}")
        return False

def get_db_connection():
    """Get a database connection from the pool"""
    try:
        if db_pool is None:
            if not init_db_pool():
                return None
        return db_pool.get_connection()
    except Exception as e:
        logger.error(f"Error getting database connection: {e}")
        return None

def init_db():
    """Initialize database tables"""
    conn = get_db_connection()
    if conn is None:
        logger.error("Failed to connect to database. Skipping table creation.")
        return
    
    cursor = conn.cursor()
    
    try:
        # Create vendors table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vendors (
                id VARCHAR(255) PRIMARY KEY,
                contact_name VARCHAR(255) NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                phone VARCHAR(20) NOT NULL,
                business_address TEXT NOT NULL,
                state VARCHAR(100) NOT NULL,
                local_government VARCHAR(100) NOT NULL,
                category ENUM('manufacturer', 'servicing_vendor', 'contractor') NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                status ENUM('pending', 'approved', 'rejected') DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            )
        ''')
        
        # Create vendor_documents table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vendor_documents (
                id VARCHAR(255) PRIMARY KEY,
                vendor_id VARCHAR(255) NOT NULL,
                document_type VARCHAR(100) NOT NULL,
                document_path VARCHAR(255) NOT NULL,
                uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (vendor_id) REFERENCES vendors(id) ON DELETE CASCADE
            )
        ''')

        cursor.execute('''
                CREATE TABLE IF NOT EXISTS mobile_vendors (
                    id VARCHAR(255) PRIMARY KEY,
                    full_name VARCHAR(255) NOT NULL,
                    username VARCHAR(100) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
        ''')
        
        # Create qr_codes table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS qr_codes (
                id VARCHAR(255) PRIMARY KEY,
                vendor_id VARCHAR(255) NOT NULL,
                product_type ENUM('existing_extinguisher', 'new_extinguisher', 'dcp_sachet') NOT NULL,
                size VARCHAR(10) NOT NULL,
                type VARCHAR(5) NOT NULL,
                qr_image TEXT NOT NULL,
                status ENUM('active', 'inactive', 'pending') DEFAULT 'inactive',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                activated_at TIMESTAMP NULL,
                FOREIGN KEY (vendor_id) REFERENCES vendors(id) ON DELETE CASCADE
            )
        ''')
        
        # Create table for existing fire extinguishers
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS existing_extinguishers (
                id VARCHAR(255) PRIMARY KEY,
                qr_code_id VARCHAR(255) NOT NULL,
                plate_number VARCHAR(100),
                building_address TEXT,
                manufacturing_date DATE NOT NULL,
                expiry_date DATE NOT NULL,
                engraved_id VARCHAR(100) NOT NULL,
                phone_number VARCHAR(20),
                manufacturer_name VARCHAR(255) NOT NULL,
                state VARCHAR(100),
                local_government VARCHAR(100),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (qr_code_id) REFERENCES qr_codes(id) ON DELETE CASCADE
            )
        ''')
        
        # Create table for new fire extinguishers
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS new_extinguishers (
                id VARCHAR(255) PRIMARY KEY,
                qr_code_id VARCHAR(255) NOT NULL,
                manufacturer_name VARCHAR(255) NOT NULL,
                son_number VARCHAR(100) NOT NULL,
                ncs_receipt_number VARCHAR(100) NOT NULL,
                ffs_fat_id VARCHAR(100) NOT NULL,
                distributor_name VARCHAR(255) NOT NULL,
                manufacturing_date DATE NOT NULL,
                expiry_date DATE NOT NULL,
                engraved_id VARCHAR(100) NOT NULL,
                phone_number VARCHAR(20) NOT NULL,
                state VARCHAR(100) NOT NULL,
                local_government VARCHAR(100) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (qr_code_id) REFERENCES qr_codes(id) ON DELETE CASCADE
            )
        ''')
        
        # Create table for DCP sachets
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS dcp_sachets (
                id VARCHAR(255) PRIMARY KEY,
                qr_code_id VARCHAR(255) NOT NULL,
                manufacturer_name VARCHAR(255) NOT NULL,
                son_number VARCHAR(100) NOT NULL,
                ncs_receipt_number VARCHAR(100) NOT NULL,
                ffs_fat_id VARCHAR(100) NOT NULL,
                distributor_name VARCHAR(255) NOT NULL,
                packaging_company VARCHAR(255) NOT NULL,
                manufacturing_date DATE NOT NULL,
                expiry_date DATE NOT NULL,
                batch_lot_id VARCHAR(100) NOT NULL,
                phone_number VARCHAR(20) NOT NULL,
                state VARCHAR(100) NOT NULL,
                local_government VARCHAR(100) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (qr_code_id) REFERENCES qr_codes(id) ON DELETE CASCADE
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sales (
                id VARCHAR(255) PRIMARY KEY,
                vendor_id VARCHAR(255) NOT NULL,
                product_type ENUM('extinguisher', 'dcp', 'accessory', 'service') NOT NULL,
                quantity INT NOT NULL DEFAULT 1,
                amount DECIMAL(10, 2) NOT NULL,
                customer_name VARCHAR(255) NOT NULL,
                customer_phone VARCHAR(20) NOT NULL,
                customer_email VARCHAR(255),
                customer_address TEXT,
                payment_method ENUM('cash', 'transfer', 'card', 'pos') NOT NULL DEFAULT 'cash',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (vendor_id) REFERENCES vendors(id) ON DELETE CASCADE
            )
        ''')

        cursor.execute('''
            ALTER TABLE sales MODIFY vendor_id VARCHAR(255) NOT NULL;
            ALTER TABLE sales DROP FOREIGN KEY sales_ibfk_1;
            ALTER TABLE vendor_entries MODIFY vendor_id VARCHAR(255) NOT NULL;
            ALTER TABLE vendor_entries DROP FOREIGN KEY vendor_entries_ibfk_1;
        ''')

        # Create services table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS services (
                id VARCHAR(255) PRIMARY KEY,
                vendor_id VARCHAR(255) NOT NULL,
                qr_code_id VARCHAR(255) NOT NULL,
                service_type ENUM('refill', 'inspection', 'maintenance', 'repair', 'installation') NOT NULL,
                description TEXT,
                amount DECIMAL(10, 2),
                customer_name VARCHAR(255),
                customer_phone VARCHAR(20),
                customer_email VARCHAR(255),
                customer_address TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (vendor_id) REFERENCES vendors(id) ON DELETE CASCADE,
                FOREIGN KEY (qr_code_id) REFERENCES qr_codes(id) ON DELETE CASCADE
            )
        ''')

        # Create decommissions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS decommissions (
                id VARCHAR(255) PRIMARY KEY,
                vendor_id VARCHAR(255) NOT NULL,
                qr_code_id VARCHAR(255) NOT NULL,
                reason ENUM('expired', 'damaged', 'faulty', 'recall', 'other') NOT NULL,
                disposal_method ENUM('recycled', 'disposed', 'returned', 'other') NOT NULL,
                disposal_date DATE NOT NULL,
                notes TEXT,
                evidence_path VARCHAR(255),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (vendor_id) REFERENCES vendors(id) ON DELETE CASCADE,
                FOREIGN KEY (qr_code_id) REFERENCES qr_codes(id) ON DELETE CASCADE
            )
        ''')

        # Additional tables for Payments, Training, Compliance and Messaging
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS payments (
                id VARCHAR(255) PRIMARY KEY,
                vendor_id VARCHAR(255) NOT NULL,
                amount DECIMAL(10, 2) NOT NULL,
                purpose VARCHAR(255) NOT NULL,
                payment_method ENUM('cash', 'transfer', 'card', 'pos') NOT NULL,
                manufacturer_share DECIMAL(10, 2),
                nfec_share DECIMAL(10, 2),
                aggregator_share DECIMAL(10, 2),
                igr_share DECIMAL(10, 2),
                vendor_share DECIMAL(10, 2),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (vendor_id) REFERENCES vendors(id) ON DELETE CASCADE
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS training_materials (
                id VARCHAR(255) PRIMARY KEY,
                title VARCHAR(255) NOT NULL,
                description TEXT,
                url VARCHAR(500) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS certifications (
                id VARCHAR(255) PRIMARY KEY,
                vendor_id VARCHAR(255) NOT NULL,
                staff_name VARCHAR(255) NOT NULL,
                staff_email VARCHAR(255),
                staff_phone VARCHAR(20),
                status ENUM('pending','approved','rejected') DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (vendor_id) REFERENCES vendors(id) ON DELETE CASCADE
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS compliance_audits (
                id VARCHAR(255) PRIMARY KEY,
                vendor_id VARCHAR(255) NOT NULL,
                audit_date DATE NOT NULL,
                description TEXT,
                result ENUM('pass','fail') NOT NULL,
                notes TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (vendor_id) REFERENCES vendors(id) ON DELETE CASCADE
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS notifications (
                id VARCHAR(255) PRIMARY KEY,
                vendor_id VARCHAR(255) NOT NULL,
                title VARCHAR(255) NOT NULL,
                message TEXT NOT NULL,
                category ENUM('anomaly','complaint','compliance','info') NOT NULL,
                is_read BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (vendor_id) REFERENCES vendors(id) ON DELETE CASCADE
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id VARCHAR(255) PRIMARY KEY,
                vendor_id VARCHAR(255) NOT NULL,
                sender_type ENUM('vendor','admin') NOT NULL,
                content TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (vendor_id) REFERENCES vendors(id) ON DELETE CASCADE
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS reports (
                id VARCHAR(255) PRIMARY KEY,
                vendor_id VARCHAR(255) NOT NULL,
                subject VARCHAR(255) NOT NULL,
                description TEXT NOT NULL,
                category ENUM('incident','suspicious_vendor','fraud','other') NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (vendor_id) REFERENCES vendors(id) ON DELETE CASCADE
            )
        ''')

        # Mobile application tables
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS mobile_entries (
                id VARCHAR(255) PRIMARY KEY,
                product_type ENUM('existing_extinguisher', 'new_extinguisher', 'dcp_sachet') NOT NULL,
                data JSON NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS training_bookings (
                id VARCHAR(255) PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                phone VARCHAR(20) NOT NULL,
                plate_or_address VARCHAR(255) NOT NULL,
                booking_date DATE NOT NULL,
                booking_time VARCHAR(20) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS mobile_payments (
                id VARCHAR(255) PRIMARY KEY,
                amount DECIMAL(10, 2) NOT NULL,
                purpose VARCHAR(255) NOT NULL,
                payment_method ENUM('cash', 'transfer', 'card', 'pos') NOT NULL,
                nfec_share DECIMAL(10, 2),
                aggregator_share DECIMAL(10, 2),
                igr_share DECIMAL(10, 2),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Vendor entries table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vendor_entries (
                id VARCHAR(255) PRIMARY KEY,
                vendor_id VARCHAR(255) NOT NULL,
                product_type ENUM('existing_extinguisher', 'new_extinguisher', 'dcp_sachet') NOT NULL,
                data JSON NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (vendor_id) REFERENCES vendors(id) ON DELETE CASCADE
            )
        ''')

        # Create officers table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS officers (
                id VARCHAR(255) PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                phone VARCHAR(20) NOT NULL,
                service_number VARCHAR(100) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        conn.commit()
        logger.info("Database tables created successfully")

        # Seed training materials if none exist
        cursor.execute('SELECT COUNT(*) FROM training_materials')
        count = cursor.fetchone()[0]
        if count == 0:
            seed_materials = [
                (str(uuid.uuid4()), 'Fire Extinguisher Basics',
                 'Overview of fire extinguisher types, classifications and proper use.',
                 'https://example.com/training/fire-extinguisher-basics.pdf'),
                (str(uuid.uuid4()), 'DCP Handling & Safety',
                 'Safety guidelines for handling Dry Chemical Powder (DCP) sachets and extinguishers.',
                 'https://example.com/training/dcp-safety.pdf'),
                (str(uuid.uuid4()), 'NFEC Compliance Training',
                 'Regulatory requirements and compliance procedures for servicing vendors and contractors.',
                 'https://example.com/training/nfec-compliance.pdf')
            ]
            cursor.executemany('''
                INSERT INTO training_materials (id, title, description, url)
                VALUES (%s, %s, %s, %s)
            ''', seed_materials)
            conn.commit()
            logger.info("Training materials seeded successfully")
            
    except Exception as e:
        logger.error(f"Error initializing database: {e}")
        conn.rollback()
    finally:
        cursor.close()
        conn.close()


def get_mobile_vendor_by_id(vendor_id):
    conn = get_db_connection()
    if conn is None:
        return None
        
    cursor = conn.cursor(dictionary=True)
    vendor = None
    
    try:
        cursor.execute('SELECT id, full_name, username FROM mobile_vendors WHERE id = %s', (vendor_id,))
        vendor = cursor.fetchone()
    except Exception as e:
        logger.error(f"Error fetching mobile vendor by ID: {e}")
    finally:
        cursor.close()
        conn.close()
    
    return vendor

# JWT token required decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        
        if not token:
            return jsonify({'success': False, 'message': 'Token is missing!'}), 401
        
        try:
            if token.startswith('Bearer '):
                token = token[7:]
            
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            
            # Check if it's a mobile vendor
            if data.get('is_mobile'):
                current_user = get_mobile_vendor_by_id(data.get('vendor_id'))
                if not current_user:
                    return jsonify({'success': False, 'message': 'Mobile vendor not found!'}), 401
                # Add mobile vendor flag to the user object
                current_user['is_mobile'] = True
            else:
                # Regular vendor
                current_user = get_vendor_by_id(data.get('vendor_id'))
                if not current_user:
                    return jsonify({'success': False, 'message': 'Vendor not found!'}), 401
                current_user['is_mobile'] = False
                
        except jwt.ExpiredSignatureError:
            return jsonify({'success': False, 'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'success': False, 'message': 'Invalid token!'}), 401
        except Exception as e:
            logger.error(f"Token validation error: {e}")
            return jsonify({'success': False, 'message': 'Token is invalid!'}), 401
        
        return f(current_user, *args, **kwargs)
    
    return decorated
# Helper function to get vendor by ID
def get_vendor_by_id(vendor_id):
    conn = get_db_connection()
    if conn is None:
        return None
        
    cursor = conn.cursor(dictionary=True)
    vendor = None
    
    try:
        cursor.execute('SELECT id, contact_name, email, phone, business_address, state, local_government, category, status FROM vendors WHERE id = %s', (vendor_id,))
        vendor = cursor.fetchone()
    except Exception as e:
        logger.error(f"Error fetching vendor by ID: {e}")
    finally:
        cursor.close()
        conn.close()
    
    return vendor

# Helper function to get vendor by email
def get_vendor_by_email(email):
    conn = get_db_connection()
    if conn is None:
        return None
        
    cursor = conn.cursor(dictionary=True)
    vendor = None
    
    try:
        cursor.execute('SELECT id, contact_name, email, phone, password_hash, status FROM vendors WHERE email = %s', (email,))
        vendor = cursor.fetchone()
    except Exception as e:
        logger.error(f"Error fetching vendor by email: {e}")
    finally:
        cursor.close()
        conn.close()
    
    return vendor

@app.route('/api/vendors/register', methods=['POST'])
def register_vendor():
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'success': False, 'message': 'No data provided'}), 400
        
        required_fields = ['contactName', 'email', 'phone', 'businessAddress', 'state', 'localGovernment', 'category', 'password']
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({
                    'success': False,
                    'message': f'{field} is required'
                }), 400
        
        existing_vendor = get_vendor_by_email(data['email'])
        if existing_vendor:
            return jsonify({
                'success': False,
                'message': 'Vendor with this email already exists'
            }), 409
        
        vendor_id = str(uuid.uuid4())
        password_hash = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO vendors (id, contact_name, email, phone, 
                business_address, state, local_government, category, password_hash)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            ''', (
                vendor_id,
                data['contactName'],
                data['email'],
                data['phone'],
                data['businessAddress'],
                data['state'],
                data['localGovernment'],
                data['category'],
                password_hash
            ))
            
            conn.commit()
            
            return jsonify({
                'success': True,
                'message': 'Vendor registration submitted successfully. Awaiting approval.',
                'vendorId': vendor_id
            }), 201
            
        except mysql.connector.Error as err:
            conn.rollback()
            logger.error(f"Database error in vendor registration: {err}")
            return jsonify({
                'success': False,
                'message': f'Database error: {err}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        logger.error(f"Error in vendor registration: {e}")
        return jsonify({
            'success': False,
            'message': f'Error: {str(e)}'
        }), 500

@app.route('/api/vendors/login', methods=['POST'])
def login_vendor():
    try:
        data = request.get_json()
        
        if not data or not data.get('email') or not data.get('password'):
            return jsonify({
                'success': False,
                'message': 'Email and password are required'
            }), 400
        
        vendor = get_vendor_by_email(data['email'])
        
        if not vendor:
            return jsonify({
                'success': False,
                'message': 'Invalid email or password'
            }), 401
        
        if not bcrypt.checkpw(data['password'].encode('utf-8'), vendor['password_hash'].encode('utf-8')):
            return jsonify({
                'success': False,
                'message': 'Invalid email or password'
            }), 401
        
        if vendor['status'] != 'approved':
            return jsonify({
                'success': False,
                'message': 'Your account is pending approval. Please contact administrator.'
            }), 403
        
        token = jwt.encode({
            'vendor_id': vendor['id'],
            'email': vendor['email'],
            'exp': datetime.now(timezone.utc) + timedelta(hours=24)
        }, app.config['SECRET_KEY'], algorithm="HS256")
        
        return jsonify({
            'success': True,
            'message': 'Login successful',
            'token': token,
            'vendor': {
                'id': vendor['id'],
                'contactName': vendor['contact_name'],
                'email': vendor['email'],
                'phone': vendor['phone'],
                'status': vendor['status']
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Error in vendor login: {e}")
        return jsonify({
            'success': False,
            'message': f'Error: {str(e)}'
        }), 500

@app.route('/api/vendors/profile', methods=['GET'])
@token_required
def get_vendor_profile(current_user):
    try:
        return jsonify({
            'success': True,
            'vendor': current_user
        }), 200
        
    except Exception as e:
        logger.error(f"Error fetching vendor profile: {e}")
        return jsonify({
            'success': False,
            'message': f'Error: {str(e)}'
        }), 500

@app.route('/api/vendors', methods=['GET'])
@token_required
def get_vendors(current_user):
    try:
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor(dictionary=True)
        
        try:
            cursor.execute('SELECT id, contact_name, email, phone, business_address, state, local_government, category, status, created_at FROM vendors ORDER BY created_at DESC')
            vendors = cursor.fetchall()
            
            return jsonify({
                'success': True,
                'vendors': vendors
            }), 200
            
        except Exception as e:
            logger.error(f"Error fetching vendors: {e}")
            return jsonify({
                'success': False,
                'message': f'Error fetching vendors: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        logger.error(f"Error in get_vendors: {e}")
        return jsonify({
            'success': False,
            'message': f'Error: {str(e)}'
        }), 500

@app.route('/api/vendor/generate-qr', methods=['POST'])
@token_required
def generate_qr_code(current_user):
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'success': False, 'message': 'No data provided'}), 400
        
        required_fields = ['productType', 'size', 'type', 'quantity']
        
        if data['productType'] == 'existing_extinguisher':
            required_fields.extend(['plateNumber', 'buildingAddress', 'manufacturingDate', 
                                  'expiryDate', 'engravedId', 'phoneNumber', 
                                  'manufacturerName', 'state', 'localGovernment'])
        elif data['productType'] == 'new_extinguisher':
            required_fields.extend(['manufacturerName', 'sonNumber', 'ncsReceiptNumber', 
                                  'ffsFATId', 'distributorName', 'manufacturingDate', 
                                  'expiryDate', 'engravedId', 'phoneNumber', 
                                  'state', 'localGovernment'])
        elif data['productType'] == 'dcp_sachet':
            required_fields.extend(['manufacturerName', 'sonNumber', 'ncsReceiptNumber', 
                                  'ffsFATId', 'distributorName', 'packagingCompany', 
                                  'manufacturingDate', 'expiryDate', 'batchLotId', 
                                  'phoneNumber', 'state', 'localGovernment'])
        
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({
                    'success': False,
                    'message': f'{field} is required'
                }), 400
        
        quantity = min(max(1, int(data['quantity'])), 100)
        
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor()
        
        try:
            generated_codes = []
            
            for i in range(quantity):
                qr_id = str(uuid.uuid4())
                
                # Create URL instead of JSON data
                qr_url = f"https://nfdrc.ng/feims/scan.php/{qr_id}"
                
                qr = qrcode.QRCode(
                    version=1,
                    error_correction=qrcode.constants.ERROR_CORRECT_L,
                    box_size=10,
                    border=4,
                )
                qr.add_data(qr_url)
                qr.make(fit=True)
                
                img = qr.make_image(fill_color="#ff7b00", back_color="white")
                
                buffered = io.BytesIO()
                img.save(buffered, format="PNG")
                img_str = base64.b64encode(buffered.getvalue()).decode()
                
                cursor.execute('''
                    INSERT INTO qr_codes (id, vendor_id, product_type, size, type, qr_image, status)
                    VALUES (%s, %s, %s, %s, %s, %s, 'inactive')
                ''', (
                    qr_id,
                    current_user['id'],
                    data['productType'],
                    data['size'],
                    data['type'],
                    img_str
                ))
                
                if data['productType'] == 'existing_extinguisher':
                    extinguisher_id = str(uuid.uuid4())
                    cursor.execute('''
                        INSERT INTO existing_extinguishers 
                        (id, qr_code_id, plate_number, building_address, manufacturing_date, 
                         expiry_date, engraved_id, phone_number, manufacturer_name, state, local_government)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ''', (
                        extinguisher_id, qr_id, data.get('plateNumber'), data.get('buildingAddress'),
                        data['manufacturingDate'], data['expiryDate'], data['engravedId'],
                        data['phoneNumber'], data['manufacturerName'], data['state'], data['localGovernment']
                    ))
                    
                elif data['productType'] == 'new_extinguisher':
                    extinguisher_id = str(uuid.uuid4())
                    cursor.execute('''
                        INSERT INTO new_extinguishers 
                        (id, qr_code_id, manufacturer_name, son_number, ncs_receipt_number, 
                         ffs_fat_id, distributor_name, manufacturing_date, expiry_date, 
                         engraved_id, phone_number, state, local_government)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ''', (
                        extinguisher_id, qr_id, data['manufacturerName'], data['sonNumber'],
                        data['ncsReceiptNumber'], data['ffsFATId'], data['distributorName'],
                        data['manufacturingDate'], data['expiryDate'], data['engravedId'],
                        data['phoneNumber'], data['state'], data['localGovernment']
                    ))
                    
                elif data['productType'] == 'dcp_sachet':
                    sachet_id = str(uuid.uuid4())
                    cursor.execute('''
                        INSERT INTO dcp_sachets 
                        (id, qr_code_id, manufacturer_name, son_number, ncs_receipt_number, 
                         ffs_fat_id, distributor_name, packaging_company, manufacturing_date, 
                         expiry_date, batch_lot_id, phone_number, state, local_government)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ''', (
                        sachet_id, qr_id, data['manufacturerName'], data['sonNumber'],
                        data['ncsReceiptNumber'], data['ffsFATId'], data['distributorName'],
                        data['packagingCompany'], data['manufacturingDate'], data['expiryDate'],
                        data['batchLotId'], data['phoneNumber'], data['state'], data['localGovernment']
                    ))
                
                generated_codes.append({
                    'id': qr_id,
                    'qrImage': f"data:image/png;base64,{img_str}",
                    'url': qr_url
                })
            
            conn.commit()
            
            return jsonify({
                'success': True,
                'message': f'Successfully generated {quantity} QR codes',
                'codes': generated_codes
            }), 201
            
        except Exception as e:
            conn.rollback()
            logger.error(f"Error generating QR codes: {e}")
            return jsonify({
                'success': False,
                'message': f'Error generating QR codes: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        logger.error(f"Error in generate_qr_code: {e}")
        return jsonify({
            'success': False,
            'message': f'Error generating QR codes: {str(e)}'
        }), 500


@app.route('/api/scan/<qr_id>', methods=['GET'])
def scan_qr_code(qr_id):
    try:
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor(dictionary=True)
        
        try:
            cursor.execute('''
                SELECT id, product_type, size, type, status, created_at, activated_at, vendor_id
                FROM qr_codes WHERE id = %s
            ''', (qr_id,))
            
            qr_code = cursor.fetchone()
            
            if not qr_code:
                return jsonify({
                    'success': False,
                    'message': 'QR code not found'
                }), 404
            
            product_info = {}
            
            if qr_code['product_type'] == 'existing_extinguisher':
                cursor.execute('''
                    SELECT plate_number, building_address, manufacturing_date, expiry_date,
                           engraved_id, phone_number, manufacturer_name, state, local_government
                    FROM existing_extinguishers WHERE qr_code_id = %s
                ''', (qr_id,))
                product_info = cursor.fetchone()
                
            elif qr_code['product_type'] == 'new_extinguisher':
                cursor.execute('''
                    SELECT manufacturer_name, son_number, ncs_receipt_number, ffs_fat_id,
                           distributor_name, manufacturing_date, expiry_date, engraved_id,
                           phone_number, state, local_government
                    FROM new_extinguishers WHERE qr_code_id = %s
                ''', (qr_id,))
                product_info = cursor.fetchone()
                
            elif qr_code['product_type'] == 'dcp_sachet':
                cursor.execute('''
                    SELECT manufacturer_name, son_number, ncs_receipt_number, ffs_fat_id,
                           distributor_name, packaging_company, manufacturing_date, expiry_date,
                           batch_lot_id, phone_number, state, local_government
                    FROM dcp_sachets WHERE qr_code_id = %s
                ''', (qr_id,))
                product_info = cursor.fetchone()
            
            if not product_info:
                return jsonify({
                    'success': False,
                    'message': 'Product information not found'
                }), 404
            
            return jsonify({
                'success': True,
                'qrCode': {
                    'id': qr_code['id'],
                    'productType': qr_code['product_type'],
                    'size': qr_code['size'],
                    'type': qr_code['type'],
                    'status': qr_code['status'],
                    'createdAt': qr_code['created_at'],
                    'activatedAt': qr_code['activated_at']
                },
                'productInfo': product_info
            }), 200
            
        except Exception as e:
            logger.error(f"Error scanning QR code: {e}")
            return jsonify({
                'success': False,
                'message': f'Error scanning QR code: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        logger.error(f"Error in scan_qr_code: {e}")
        return jsonify({
            'success': False,
            'message': f'Error scanning QR code: {str(e)}'
        }), 500

@app.route('/api/vendor/qrcodes', methods=['GET'])
@token_required
def get_vendor_qr_codes(current_user):
    try:
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor(dictionary=True)
        
        try:
            cursor.execute('''
                SELECT id, product_type, size, type, status, created_at, activated_at, qr_image
                FROM qr_codes 
                WHERE vendor_id = %s 
                ORDER BY created_at DESC
            ''', (current_user['id'],))
            
            qr_codes = cursor.fetchall()
            
            return jsonify({
                'success': True,
                'qrCodes': qr_codes
            }), 200
            
        except Exception as e:
            logger.error(f"Error fetching QR codes: {e}")
            return jsonify({
                'success': False,
                'message': f'Error fetching QR codes: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        logger.error(f"Error in get_vendor_qr_codes: {e}")
        return jsonify({
            'success': False,
            'message': f'Error fetching QR codes: {str(e)}'
        }), 500


@app.route('/api/vendor/activate-qr', methods=['POST'])
@token_required
def activate_qr_code(current_user):
    """Immediate activation for vendor-provided QR ID."""
    try:
        data = request.get_json() or {}
        qr_id = data.get('qrId')
        if not qr_id:
            return jsonify({'success': False, 'message': 'QR code ID is required'}), 400

        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor(dictionary=True)

        try:
            cursor.execute('SELECT vendor_id, status FROM qr_codes WHERE id = %s', (qr_id,))
            record = cursor.fetchone()
            if not record:
                return jsonify({'success': False, 'message': 'QR code not found'}), 404

            # For mobile vendors, we don't check vendor ownership since they're activating on behalf of regular vendors
            # Mobile vendors can activate any QR code (you might want to add permission checks later)
            
            if record['status'] == 'active':
                return jsonify({'success': False, 'message': 'QR code is already active'}), 400

            # Immediate activation
            cursor.execute('UPDATE qr_codes SET status = %s, activated_at = NOW() WHERE id = %s', ('active', qr_id))
            conn.commit()
            
            return jsonify({'success': True, 'message': 'QR code activated successfully'}), 200
            
        except Exception as e:
            conn.rollback()
            logger.error(f"Error activating QR code: {e}")
            return jsonify({'success': False, 'message': f'Error activating QR code: {str(e)}'}), 500
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        logger.error(f"Error in activate_qr_code: {e}")
        return jsonify({'success': False, 'message': f'Error activating QR code: {str(e)}'}), 500

@app.route('/api/vendors/<vendor_id>', methods=['PUT'])
@token_required
def update_vendor_status(current_user, vendor_id):
    try:
        data = request.get_json()
        
        if not data or 'status' not in data or data['status'] not in ['approved', 'rejected']:
            return jsonify({
                'success': False,
                'message': 'Valid status (approved/rejected) is required'
            }), 400
        
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor()
        
        try:
            cursor.execute('UPDATE vendors SET status = %s WHERE id = %s', (data['status'], vendor_id))
            
            if cursor.rowcount == 0:
                return jsonify({
                    'success': False,
                    'message': 'Vendor not found'
                }), 404
            
            conn.commit()
            
            return jsonify({
                'success': True,
                'message': f'Vendor status updated to {data["status"]}'
            }), 200
            
        except Exception as e:
            conn.rollback()
            logger.error(f"Error updating vendor status: {e}")
            return jsonify({
                'success': False,
                'message': f'Error updating vendor status: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        logger.error(f"Error in update_vendor_status: {e}")
        return jsonify({
            'success': False,
            'message': f'Error updating vendor status: {str(e)}'
        }), 500

@app.route('/api/vendor/sales', methods=['POST'])
@token_required
def record_sale(current_user):
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'success': False, 'message': 'No data provided'}), 400
        
        required_fields = ['productType', 'amount', 'customerName', 'customerPhone']
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({
                    'success': False,
                    'message': f'{field} is required'
                }), 400
        
        sale_id = str(uuid.uuid4())
        
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor()
        
        try:
            # For mobile vendors, use their ID directly (they're not in vendors table)
            vendor_id = current_user['id']
            
            cursor.execute('''
                INSERT INTO sales 
                (id, vendor_id, product_type, quantity, amount, customer_name, customer_phone, 
                 customer_email, customer_address, payment_method)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ''', (
                sale_id,
                vendor_id,
                data['productType'],
                data.get('quantity', 1),
                data['amount'],
                data['customerName'],
                data['customerPhone'],
                data.get('customerEmail'),
                data.get('customerAddress'),
                data.get('paymentMethod', 'cash')
            ))
            
            conn.commit()
            
            return jsonify({
                'success': True,
                'message': 'Sale recorded successfully',
                'saleId': sale_id
            }), 201
            
        except Exception as e:
            conn.rollback()
            logger.error(f"Error recording sale: {e}")
            return jsonify({
                'success': False,
                'message': f'Error recording sale: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        logger.error(f"Error in record_sale: {e}")
        return jsonify({
            'success': False,
            'message': f'Error recording sale: {str(e)}'
        }), 500

@app.route('/api/vendor/sales', methods=['GET'])
@token_required
def get_sales(current_user):
    try:
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor(dictionary=True)
        
        try:
            cursor.execute('''
                SELECT id, product_type, quantity, amount, customer_name, customer_phone, 
                       payment_method, created_at
                FROM sales 
                WHERE vendor_id = %s 
                ORDER BY created_at DESC
            ''', (current_user['id'],))
            
            sales = cursor.fetchall()
            
            return jsonify({
                'success': True,
                'sales': sales
            }), 200
            
        except Exception as e:
            logger.error(f"Error fetching sales: {e}")
            return jsonify({
                'success': False,
                'message': f'Error fetching sales: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        logger.error(f"Error in get_sales: {e}")
        return jsonify({
            'success': False,
            'message': f'Error fetching sales: {str(e)}'
        }), 500

@app.route('/api/vendor/services', methods=['POST'])
@token_required
def record_service(current_user):
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'success': False, 'message': 'No data provided'}), 400
        
        required_fields = ['qrCodeId', 'serviceType', 'customerName', 'customerPhone']
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({
                    'success': False,
                    'message': f'{field} is required'
                }), 400
        
        service_id = str(uuid.uuid4())
        
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO services 
                (id, vendor_id, qr_code_id, service_type, description, amount, 
                 customer_name, customer_phone, customer_email, customer_address)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ''', (
                service_id,
                current_user['id'],
                data['qrCodeId'],
                data['serviceType'],
                data.get('description'),
                data.get('amount', 0),
                data['customerName'],
                data['customerPhone'],
                data.get('customerEmail'),
                data.get('customerAddress')
            ))
            
            conn.commit()
            
            return jsonify({
                'success': True,
                'message': 'Service recorded successfully',
                'serviceId': service_id
            }), 201
            
        except Exception as e:
            conn.rollback()
            logger.error(f"Error recording service: {e}")
            return jsonify({
                'success': False,
                'message': f'Error recording service: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        logger.error(f"Error in record_service: {e}")
        return jsonify({
            'success': False,
            'message': f'Error recording service: {str(e)}'
        }), 500

@app.route('/api/vendor/services', methods=['GET'])
@token_required
def get_services(current_user):
    try:
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor(dictionary=True)
        
        try:
            cursor.execute('''
                SELECT s.id, s.qr_code_id, s.service_type, s.description, s.amount, 
                       s.customer_name, s.customer_phone, s.created_at, q.product_type
                FROM services s
                JOIN qr_codes q ON s.qr_code_id = q.id
                WHERE s.vendor_id = %s 
                ORDER BY s.created_at DESC
            ''', (current_user['id'],))
            
            services = cursor.fetchall()
            
            return jsonify({
                'success': True,
                'services': services
            }), 200
            
        except Exception as e:
            logger.error(f"Error fetching services: {e}")
            return jsonify({
                'success': False,
                'message': f'Error fetching services: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        logger.error(f"Error in get_services: {e}")
        return jsonify({
            'success': False,
            'message': f'Error fetching services: {str(e)}'
        }), 500

@app.route('/api/vendor/decommissions', methods=['POST'])
@token_required
def record_decommission(current_user):
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'success': False, 'message': 'No data provided'}), 400
        
        required_fields = ['qrCodeId', 'reason', 'disposalMethod', 'disposalDate']
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({
                    'success': False,
                    'message': f'{field} is required'
                }), 400
        
        decommission_id = str(uuid.uuid4())
        
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO decommissions 
                (id, vendor_id, qr_code_id, reason, disposal_method, disposal_date, notes)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            ''', (
                decommission_id,
                current_user['id'],
                data['qrCodeId'],
                data['reason'],
                data['disposalMethod'],
                data['disposalDate'],
                data.get('notes')
            ))
            
            conn.commit()
            
            return jsonify({
                'success': True,
                'message': 'Decommission recorded successfully',
                'decommissionId': decommission_id
            }), 201
            
        except Exception as e:
            conn.rollback()
            logger.error(f"Error recording decommission: {e}")
            return jsonify({
                'success': False,
                'message': f'Error recording decommission: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        logger.error(f"Error in record_decommission: {e}")
        return jsonify({
            'success': False,
            'message': f'Error recording decommission: {str(e)}'
        }), 500

@app.route('/api/vendor/decommissions', methods=['GET'])
@token_required
def get_decommissions(current_user):
    try:
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor(dictionary=True)
        
        try:
            cursor.execute('''
                SELECT d.id, d.qr_code_id, d.reason, d.disposal_method, d.disposal_date, 
                       d.notes, d.created_at, q.product_type
                FROM decommissions d
                JOIN qr_codes q ON d.qr_code_id = q.id
                WHERE d.vendor_id = %s 
                ORDER BY d.created_at DESC
            ''', (current_user['id'],))
            
            decommissions = cursor.fetchall()
            
            return jsonify({
                'success': True,
                'decommissions': decommissions
            }), 200
            
        except Exception as e:
            logger.error(f"Error fetching decommissions: {e}")
            return jsonify({
                'success': False,
                'message': f'Error fetching decommissions: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        logger.error(f"Error in get_decommissions: {e}")
        return jsonify({
            'success': False,
            'message': f'Error fetching decommissions: {str(e)}'
        }), 500

@app.route('/api/admin/login', methods=['POST'])
def admin_login():
    try:
        data = request.get_json()
        
        if not data or not data.get('username') or not data.get('password'):
            return jsonify({
                'success': False,
                'message': 'Username and password are required'
            }), 400
        
        if data['username'] != ADMIN_USERNAME or data['password'] != ADMIN_PASSWORD:
            return jsonify({
                'success': False,
                'message': 'Invalid admin credentials'
            }), 401
        
        token = jwt.encode({
            'username': data['username'],
            'role': 'admin',
            'exp': datetime.now(timezone.utc) + timedelta(hours=24)
        }, app.config['SECRET_KEY'], algorithm="HS256")
        
        return jsonify({
            'success': True,
            'message': 'Admin login successful',
            'token': token
        }), 200
        
    except Exception as e:
        logger.error(f"Error in admin login: {e}")
        return jsonify({
            'success': False,
            'message': f'Error: {str(e)}'
        }), 500

@app.route('/api/admin/dashboard', methods=['GET'])
@admin_token_required
def admin_dashboard(current_admin):
    try:
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor(dictionary=True)
        
        try:
            # Get vendor counts by status
            cursor.execute('SELECT status, COUNT(*) as count FROM vendors GROUP BY status')
            vendor_counts = {row['status']: row['count'] for row in cursor.fetchall()}
            
            # Get total QR codes by status
            cursor.execute('SELECT status, COUNT(*) as count FROM qr_codes GROUP BY status')
            qr_counts = {row['status']: row['count'] for row in cursor.fetchall()}
            
            # Get recent activities
            cursor.execute('''
                (SELECT 'vendor_registration' as type, contact_name as name, created_at 
                 FROM vendors ORDER BY created_at DESC LIMIT 5)
                UNION ALL
                (SELECT 'qr_generated' as type, product_type as name, created_at 
                 FROM qr_codes ORDER BY created_at DESC LIMIT 5)
                UNION ALL
                (SELECT 'sale_recorded' as type, customer_name as name, created_at 
                 FROM sales ORDER BY created_at DESC LIMIT 5)
                ORDER BY created_at DESC LIMIT 10
            ''')
            recent_activities = cursor.fetchall()
            
            return jsonify({
                'success': True,
                'stats': {
                    'vendors': {
                        'total': sum(vendor_counts.values()),
                        'approved': vendor_counts.get('approved', 0),
                        'pending': vendor_counts.get('pending', 0),
                        'rejected': vendor_counts.get('rejected', 0)
                    },
                    'qrCodes': {
                        'total': sum(qr_counts.values()),
                        'active': qr_counts.get('active', 0),
                        'inactive': qr_counts.get('inactive', 0),
                        'pending': qr_counts.get('pending', 0)
                    }
                },
                'recentActivities': recent_activities
            }), 200
            
        except Exception as e:
            logger.error(f"Error fetching dashboard data: {e}")
            return jsonify({
                'success': False,
                'message': f'Error fetching dashboard data: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        logger.error(f"Error in admin_dashboard: {e}")
        return jsonify({
            'success': False,
            'message': f'Error fetching dashboard data: {str(e)}'
        }), 500

@app.route('/api/admin/vendors', methods=['GET'])
@admin_token_required
def admin_get_vendors(current_admin):
    try:
        status = request.args.get('status')
        
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor(dictionary=True)
        
        try:
            if status and status in ['pending', 'approved', 'rejected']:
                cursor.execute('''
                    SELECT id, contact_name, email, phone, business_address, state, 
                           local_government, category, status, created_at
                    FROM vendors 
                    WHERE status = %s
                    ORDER BY created_at DESC
                ''', (status,))
            else:
                cursor.execute('''
                    SELECT id, contact_name, email, phone, business_address, state, 
                           local_government, category, status, created_at
                    FROM vendors 
                    ORDER BY created_at DESC
                ''')
            
            vendors = cursor.fetchall()
            
            return jsonify({
                'success': True,
                'vendors': vendors
            }), 200
            
        except Exception as e:
            logger.error(f"Error fetching vendors: {e}")
            return jsonify({
                'success': False,
                'message': f'Error fetching vendors: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        logger.error(f"Error in admin_get_vendors: {e}")
        return jsonify({
            'success': False,
            'message': f'Error fetching vendors: {str(e)}'
        }), 500

@app.route('/api/admin/vendors/<vendor_id>/approve', methods=['POST'])
@admin_token_required
def admin_approve_vendor(current_admin, vendor_id):
    try:
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor()
        
        try:
            cursor.execute('UPDATE vendors SET status = "approved" WHERE id = %s', (vendor_id,))
            
            if cursor.rowcount == 0:
                return jsonify({
                    'success': False,
                    'message': 'Vendor not found'
                }), 404
            
            conn.commit()
            
            return jsonify({
                'success': True,
                'message': 'Vendor approved successfully'
            }), 200
            
        except Exception as e:
            conn.rollback()
            logger.error(f"Error approving vendor: {e}")
            return jsonify({
                'success': False,
                'message': f'Error approving vendor: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        logger.error(f"Error in admin_approve_vendor: {e}")
        return jsonify({
            'success': False,
            'message': f'Error approving vendor: {str(e)}'
        }), 500

@app.route('/api/admin/vendors/<vendor_id>/reject', methods=['POST'])
@admin_token_required
def admin_reject_vendor(current_admin, vendor_id):
    try:
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor()
        
        try:
            cursor.execute('UPDATE vendors SET status = "rejected" WHERE id = %s', (vendor_id,))
            
            if cursor.rowcount == 0:
                return jsonify({
                    'success': False,
                    'message': 'Vendor not found'
                }), 404
            
            conn.commit()
            
            return jsonify({
                'success': True,
                'message': 'Vendor rejected successfully'
            }), 200
            
        except Exception as e:
            conn.rollback()
            logger.error(f"Error rejecting vendor: {e}")
            return jsonify({
                'success': False,
                'message': f'Error rejecting vendor: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        logger.error(f"Error in admin_reject_vendor: {e}")
        return jsonify({
            'success': False,
            'message': f'Error rejecting vendor: {str(e)}'
        }), 500

@app.route('/api/admin/qr-codes', methods=['GET'])
@admin_token_required
def admin_get_qr_codes(current_admin):
    try:
        status = request.args.get('status')
        vendor_id = request.args.get('vendor_id')
        
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor(dictionary=True)
        
        try:
            query = '''
                SELECT q.id, q.product_type, q.size, q.type, q.status, q.created_at, q.activated_at,
                       v.contact_name as vendor_name, v.email as vendor_email
                FROM qr_codes q
                JOIN vendors v ON q.vendor_id = v.id
            '''
            params = []
            
            conditions = []
            if status and status in ['active', 'inactive', 'pending']:
                conditions.append('q.status = %s')
                params.append(status)
            if vendor_id:
                conditions.append('q.vendor_id = %s')
                params.append(vendor_id)
            
            if conditions:
                query += ' WHERE ' + ' AND '.join(conditions)
            
            query += ' ORDER BY q.created_at DESC'
            
            cursor.execute(query, params)
            qr_codes = cursor.fetchall()
            
            return jsonify({
                'success': True,
                'qrCodes': qr_codes
            }), 200
            
        except Exception as e:
            logger.error(f"Error fetching QR codes: {e}")
            return jsonify({
                'success': False,
                'message': f'Error fetching QR codes: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        logger.error(f"Error in admin_get_qr_codes: {e}")
        return jsonify({
            'success': False,
            'message': f'Error fetching QR codes: {str(e)}'
        }), 500

@app.route('/api/admin/analytics', methods=['GET'])
@admin_token_required
def admin_analytics(current_admin):
    try:
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor(dictionary=True)
        
        try:
            # Get vendor registrations by month
            cursor.execute('''
                SELECT DATE_FORMAT(created_at, '%Y-%m') as month, COUNT(*) as count
                FROM vendors 
                WHERE created_at >= DATE_SUB(NOW(), INTERVAL 6 MONTH)
                GROUP BY month 
                ORDER BY month
            ''')
            vendor_registrations = cursor.fetchall()
            
            # Get QR code generations by month
            cursor.execute('''
                SELECT DATE_FORMAT(created_at, '%Y-%m') as month, COUNT(*) as count
                FROM qr_codes 
                WHERE created_at >= DATE_SUB(NOW(), INTERVAL 6 MONTH)
                GROUP BY month 
                ORDER BY month
            ''')
            qr_generations = cursor.fetchall()
            
            # Get sales by product type
            cursor.execute('''
                SELECT product_type, COUNT(*) as count, SUM(amount) as revenue
                FROM sales 
                GROUP BY product_type
            ''')
            sales_by_product = cursor.fetchall()
            
            return jsonify({
                'success': True,
                'analytics': {
                    'vendorRegistrations': vendor_registrations,
                    'qrGenerations': qr_generations,
                    'salesByProduct': sales_by_product
                }
            }), 200
            
        except Exception as e:
            logger.error(f"Error fetching analytics: {e}")
            return jsonify({
                'success': False,
                'message': f'Error fetching analytics: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        logger.error(f"Error in admin_analytics: {e}")
        return jsonify({
            'success': False,
            'message': f'Error fetching analytics: {str(e)}'
        }), 500

@app.route('/api/training-materials', methods=['GET'])
@token_required
def get_training_materials(current_user):
    try:
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor(dictionary=True)
        
        try:
            cursor.execute('SELECT id, title, description, url, created_at FROM training_materials ORDER BY created_at DESC')
            materials = cursor.fetchall()
            
            return jsonify({
                'success': True,
                'materials': materials
            }), 200
            
        except Exception as e:
            logger.error(f"Error fetching training materials: {e}")
            return jsonify({
                'success': False,
                'message': f'Error fetching training materials: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        logger.error(f"Error in get_training_materials: {e}")
        return jsonify({
            'success': False,
            'message': f'Error fetching training materials: {str(e)}'
        }), 500

@app.route('/api/training-materials', methods=['POST'])
@admin_token_required
def add_training_material(current_admin):
    try:
        data = request.get_json()
        
        if not data or not data.get('title') or not data.get('url'):
            return jsonify({
                'success': False,
                'message': 'Title and URL are required'
            }), 400
        
        material_id = str(uuid.uuid4())
        
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO training_materials (id, title, description, url)
                VALUES (%s, %s, %s, %s)
            ''', (
                material_id,
                data['title'],
                data.get('description'),
                data['url']
            ))
            
            conn.commit()
            
            return jsonify({
                'success': True,
                'message': 'Training material added successfully',
                'materialId': material_id
            }), 201
            
        except Exception as e:
            conn.rollback()
            logger.error(f"Error adding training material: {e}")
            return jsonify({
                'success': False,
                'message': f'Error adding training material: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        logger.error(f"Error in add_training_material: {e}")
        return jsonify({
            'success': False,
            'message': f'Error adding training material: {str(e)}'
        }), 500

@app.route('/api/notifications', methods=['GET'])
@token_required
def get_notifications(current_user):
    try:
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor(dictionary=True)
        
        try:
            cursor.execute('''
                SELECT id, title, message, category, is_read, created_at
                FROM notifications 
                WHERE vendor_id = %s 
                ORDER BY created_at DESC
            ''', (current_user['id'],))
            
            notifications = cursor.fetchall()
            
            return jsonify({
                'success': True,
                'notifications': notifications
            }), 200
            
        except Exception as e:
            logger.error(f"Error fetching notifications: {e}")
            return jsonify({
                'success': False,
                'message': f'Error fetching notifications: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        logger.error(f"Error in get_notifications: {e}")
        return jsonify({
            'success': False,
            'message': f'Error fetching notifications: {str(e)}'
        }), 500

@app.route('/api/notifications/<notification_id>/read', methods=['PUT'])
@token_required
def mark_notification_read(current_user, notification_id):
    try:
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                UPDATE notifications 
                SET is_read = TRUE 
                WHERE id = %s AND vendor_id = %s
            ''', (notification_id, current_user['id']))
            
            conn.commit()
            
            return jsonify({
                'success': True,
                'message': 'Notification marked as read'
            }), 200
            
        except Exception as e:
            conn.rollback()
            logger.error(f"Error updating notification: {e}")
            return jsonify({
                'success': False,
                'message': f'Error updating notification: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        logger.error(f"Error in mark_notification_read: {e}")
        return jsonify({
            'success': False,
            'message': f'Error updating notification: {str(e)}'
        }), 500

@app.route('/api/messages', methods=['GET'])
@token_required
def get_messages(current_user):
    try:
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor(dictionary=True)
        
        try:
            cursor.execute('''
                SELECT id, sender_type, content, created_at
                FROM messages 
                WHERE vendor_id = %s 
                ORDER BY created_at DESC
            ''', (current_user['id'],))
            
            messages = cursor.fetchall()
            
            return jsonify({
                'success': True,
                'messages': messages
            }), 200
            
        except Exception as e:
            logger.error(f"Error fetching messages: {e}")
            return jsonify({
                'success': False,
                'message': f'Error fetching messages: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        logger.error(f"Error in get_messages: {e}")
        return jsonify({
            'success': False,
            'message': f'Error fetching messages: {str(e)}'
        }), 500

@app.route('/api/messages', methods=['POST'])
@token_required
def send_message(current_user):
    try:
        data = request.get_json()
        
        if not data or not data.get('content'):
            return jsonify({
                'success': False,
                'message': 'Message content is required'
            }), 400
        
        message_id = str(uuid.uuid4())
        
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO messages (id, vendor_id, sender_type, content)
                VALUES (%s, %s, %s, %s)
            ''', (
                message_id,
                current_user['id'],
                'vendor',
                data['content']
            ))
            
            conn.commit()
            
            return jsonify({
                'success': True,
                'message': 'Message sent successfully',
                'messageId': message_id
            }), 201
            
        except Exception as e:
            conn.rollback()
            logger.error(f"Error sending message: {e}")
            return jsonify({
                'success': False,
                'message': f'Error sending message: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        logger.error(f"Error in send_message: {e}")
        return jsonify({
            'success': False,
            'message': f'Error sending message: {str(e)}'
        }), 500

@app.route('/api/reports', methods=['POST'])
@token_required
def submit_report(current_user):
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'success': False, 'message': 'No data provided'}), 400
        
        required_fields = ['subject', 'description', 'category']
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({
                    'success': False,
                    'message': f'{field} is required'
                }), 400
        
        report_id = str(uuid.uuid4())
        
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO reports (id, vendor_id, subject, description, category)
                VALUES (%s, %s, %s, %s, %s)
            ''', (
                report_id,
                current_user['id'],
                data['subject'],
                data['description'],
                data['category']
            ))
            
            conn.commit()
            
            return jsonify({
                'success': True,
                'message': 'Report submitted successfully',
                'reportId': report_id
            }), 201
            
        except Exception as e:
            conn.rollback()
            logger.error(f"Error submitting report: {e}")
            return jsonify({
                'success': False,
                'message': f'Error submitting report: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        logger.error(f"Error in submit_report: {e}")
        return jsonify({
            'success': False,
            'message': f'Error submitting report: {str(e)}'
        }), 500
    

@app.route('/api/mobile/vendors/register', methods=['POST'])
def register_mobile_vendor():
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'success': False, 'message': 'No data provided'}), 400
        
        required_fields = ['fullName', 'username', 'password']
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({
                    'success': False,
                    'message': f'{field} is required'
                }), 400
        
        # Validate username format
        if not re.match(r'^[a-zA-Z0-9_]{3,20}$', data['username']):
            return jsonify({
                'success': False,
                'message': 'Username must be 3-20 characters and can only contain letters, numbers, and underscores'
            }), 400
        
        # Check if username already exists
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor(dictionary=True)
        
        try:
            cursor.execute('SELECT id FROM mobile_vendors WHERE username = %s', (data['username'],))
            existing_vendor = cursor.fetchone()
            
            if existing_vendor:
                return jsonify({
                    'success': False,
                    'message': 'Username already exists'
                }), 409
            
            # Create the mobile_vendors table if it doesn't exist
            
            vendor_id = str(uuid.uuid4())
            password_hash = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            
            cursor.execute('''
                INSERT INTO mobile_vendors (id, full_name, username, password_hash)
                VALUES (%s, %s, %s, %s)
            ''', (vendor_id, data['fullName'], data['username'], password_hash))
            
            conn.commit()
            
            return jsonify({
                'success': True,
                'message': 'Mobile vendor registered successfully',
                'vendorId': vendor_id
            }), 201
            
        except Exception as e:
            conn.rollback()
            logger.error(f"Error registering mobile vendor: {e}")
            return jsonify({
                'success': False,
                'message': f'Error registering mobile vendor: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        logger.error(f"Error in register_mobile_vendor: {e}")
        return jsonify({
            'success': False,
            'message': f'Error: {str(e)}'
        }), 500

@app.route('/api/mobile/vendors/login', methods=['POST'])
def login_mobile_vendor():
    try:
        data = request.get_json()
        
        if not data or not data.get('username') or not data.get('password'):
            return jsonify({
                'success': False,
                'message': 'Username and password are required'
            }), 400
        
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor(dictionary=True)
        
        try:
            # Create the mobile_vendors table if it doesn't exist
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS mobile_vendors (
                    id VARCHAR(255) PRIMARY KEY,
                    full_name VARCHAR(255) NOT NULL,
                    username VARCHAR(100) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            cursor.execute('SELECT id, full_name, username, password_hash FROM mobile_vendors WHERE username = %s', (data['username'],))
            vendor = cursor.fetchone()
            
            if not vendor:
                return jsonify({
                    'success': False,
                    'message': 'Invalid username or password'
                }), 401
            
            if not bcrypt.checkpw(data['password'].encode('utf-8'), vendor['password_hash'].encode('utf-8')):
                return jsonify({
                    'success': False,
                    'message': 'Invalid username or password'
                }), 401
            
            # Generate JWT token for mobile vendors with vendor_id from mobile_vendors table
            token = jwt.encode({
                'vendor_id': vendor['id'],  # This is the ID from mobile_vendors table
                'username': vendor['username'],
                'is_mobile': True,  # Add flag to identify mobile vendors
                'exp': datetime.now(timezone.utc) + timedelta(hours=24)
            }, app.config['SECRET_KEY'], algorithm="HS256")
            
            return jsonify({
                'success': True,
                'message': 'Login successful',
                'token': token,
                'vendor': {
                    'id': vendor['id'],
                    'fullName': vendor['full_name'],
                    'username': vendor['username'],
                    'isMobile': True
                }
            }), 200
            
        except Exception as e:
            logger.error(f"Error in mobile vendor login: {e}")
            return jsonify({
                'success': False,
                'message': f'Error: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        logger.error(f"Error in login_mobile_vendor: {e}")
        return jsonify({
            'success': False,
            'message': f'Error: {str(e)}'
        }), 500

@app.route('/api/mobile/register', methods=['POST'])
def mobile_register():
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'success': False, 'message': 'No data provided'}), 400
        
        required_fields = ['name', 'phone', 'plateOrAddress', 'bookingDate', 'bookingTime']
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({
                    'success': False,
                    'message': f'{field} is required'
                }), 400
        
        booking_id = str(uuid.uuid4())
        
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO training_bookings 
                (id, name, phone, plate_or_address, booking_date, booking_time)
                VALUES (%s, %s, %s, %s, %s, %s)
            ''', (
                booking_id,
                data['name'],
                data['phone'],
                data['plateOrAddress'],
                data['bookingDate'],
                data['bookingTime']
            ))
            
            conn.commit()
            
            return jsonify({
                'success': True,
                'message': 'Training booking submitted successfully',
                'bookingId': booking_id
            }), 201
            
        except Exception as e:
            conn.rollback()
            logger.error(f"Error submitting training booking: {e}")
            return jsonify({
                'success': False,
                'message': f'Error submitting training booking: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        logger.error(f"Error in mobile_register: {e}")
        return jsonify({
            'success': False,
            'message': f'Error submitting training booking: {str(e)}'
        }), 500

@app.route('/api/mobile/scan/<qr_id>', methods=['GET'])
def mobile_scan_qr_code(qr_id):
    try:
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor(dictionary=True)
        
        try:
            cursor.execute('''
                SELECT id, product_type, size, type, status, created_at, activated_at
                FROM qr_codes WHERE id = %s
            ''', (qr_id,))
            
            qr_code = cursor.fetchone()
            
            if not qr_code:
                return jsonify({
                    'success': False,
                    'message': 'QR code not found'
                }), 404
            
            product_info = {}
            
            if qr_code['product_type'] == 'existing_extinguisher':
                cursor.execute('''
                    SELECT plate_number, building_address, manufacturing_date, expiry_date,
                           engraved_id, phone_number, manufacturer_name, state, local_government
                    FROM existing_extinguishers WHERE qr_code_id = %s
                ''', (qr_id,))
                product_info = cursor.fetchone()
                
            elif qr_code['product_type'] == 'new_extinguisher':
                cursor.execute('''
                    SELECT manufacturer_name, son_number, ncs_receipt_number, ffs_fat_id,
                           distributor_name, manufacturing_date, expiry_date, engraved_id,
                           phone_number, state, local_government
                    FROM new_extinguishers WHERE qr_code_id = %s
                ''', (qr_id,))
                product_info = cursor.fetchone()
                
            elif qr_code['product_type'] == 'dcp_sachet':
                cursor.execute('''
                    SELECT manufacturer_name, son_number, ncs_receipt_number, ffs_fat_id,
                           distributor_name, packaging_company, manufacturing_date, expiry_date,
                           batch_lot_id, phone_number, state, local_government
                    FROM dcp_sachets WHERE qr_code_id = %s
                ''', (qr_id,))
                product_info = cursor.fetchone()
            
            if not product_info:
                return jsonify({
                    'success': False,
                    'message': 'Product information not found'
                }), 404
            
            return jsonify({
                'success': True,
                'qrCode': {
                    'id': qr_code['id'],
                    'productType': qr_code['product_type'],
                    'size': qr_code['size'],
                    'type': qr_code['type'],
                    'status': qr_code['status'],
                    'createdAt': qr_code['created_at'],
                    'activatedAt': qr_code['activated_at']
                },
                'productInfo': product_info
            }), 200
            
        except Exception as e:
            logger.error(f"Error scanning QR code: {e}")
            return jsonify({
                'success': False,
                'message': f'Error scanning QR code: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        logger.error(f"Error in mobile_scan_qr_code: {e}")
        return jsonify({
            'success': False,
            'message': f'Error scanning QR code: {str(e)}'
        }), 500

@app.route('/api/mobile/payment', methods=['POST'])
def mobile_payment():
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'success': False, 'message': 'No data provided'}), 400
        
        required_fields = ['amount', 'purpose', 'paymentMethod']
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({
                    'success': False,
                    'message': f'{field} is required'
                }), 400
        
        payment_id = str(uuid.uuid4())
        
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO mobile_payments 
                (id, amount, purpose, payment_method, nfec_share, aggregator_share, igr_share)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            ''', (
                payment_id,
                data['amount'],
                data['purpose'],
                data['paymentMethod'],
                data.get('nfecShare', 0),
                data.get('aggregatorShare', 0),
                data.get('igrShare', 0)
            ))
            
            conn.commit()
            
            return jsonify({
                'success': True,
                'message': 'Payment recorded successfully',
                'paymentId': payment_id
            }), 201
            
        except Exception as e:
            conn.rollback()
            logger.error(f"Error recording payment: {e}")
            return jsonify({
                'success': False,
                'message': f'Error recording payment: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        logger.error(f"Error in mobile_payment: {e}")
        return jsonify({
            'success': False,
            'message': f'Error recording payment: {str(e)}'
        }), 500

@app.route('/api/mobile/entry', methods=['POST'])
def mobile_entry():
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'success': False, 'message': 'No data provided'}), 400
        
        required_fields = ['productType', 'data']
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({
                    'success': False,
                    'message': f'{field} is required'
                }), 400
        
        entry_id = str(uuid.uuid4())
        
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO mobile_entries 
                (id, product_type, data)
                VALUES (%s, %s, %s)
            ''', (
                entry_id,
                data['productType'],
                json.dumps(data['data'])
            ))
            
            conn.commit()
            
            return jsonify({
                'success': True,
                'message': 'Entry submitted successfully',
                'entryId': entry_id
            }), 201
            
        except Exception as e:
            conn.rollback()
            logger.error(f"Error submitting entry: {e}")
            return jsonify({
                'success': False,
                'message': f'Error submitting entry: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        logger.error(f"Error in mobile_entry: {e}")
        return jsonify({
            'success': False,
            'message': f'Error submitting entry: {str(e)}'
        }), 500

@app.route('/api/vendor/entries', methods=['POST'])
@token_required
def vendor_entry(current_user):
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'success': False, 'message': 'No data provided'}), 400
        
        required_fields = ['productType', 'data']
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({
                    'success': False,
                    'message': f'{field} is required'
                }), 400
        
        entry_id = str(uuid.uuid4())
        
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor()
        
        try:
            # For mobile vendors, use their ID directly
            vendor_id = current_user['id']
            
            cursor.execute('''
                INSERT INTO vendor_entries 
                (id, vendor_id, product_type, data)
                VALUES (%s, %s, %s, %s)
            ''', (
                entry_id,
                vendor_id,
                data['productType'],
                json.dumps(data['data'])
            ))
            
            conn.commit()
            
            return jsonify({
                'success': True,
                'message': 'Entry submitted successfully',
                'entryId': entry_id
            }), 201
            
        except Exception as e:
            conn.rollback()
            logger.error(f"Error submitting entry: {e}")
            return jsonify({
                'success': False,
                'message': f'Error submitting entry: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        logger.error(f"Error in vendor_entry: {e}")
        return jsonify({
            'success': False,
            'message': f'Error submitting entry: {str(e)}'
        }), 500

@app.route('/api/officers', methods=['POST'])
def register_officer():
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'success': False, 'message': 'No data provided'}), 400
        
        required_fields = ['name', 'phone', 'serviceNumber']
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({
                    'success': False,
                    'message': f'{field} is required'
                }), 400
        
        officer_id = str(uuid.uuid4())
        
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO officers 
                (id, name, phone, service_number)
                VALUES (%s, %s, %s, %s)
            ''', (
                officer_id,
                data['name'],
                data['phone'],
                data['serviceNumber']
            ))
            
            conn.commit()
            
            return jsonify({
                'success': True,
                'message': 'Officer registered successfully',
                'officerId': officer_id
            }), 201
            
        except Exception as e:
            conn.rollback()
            logger.error(f"Error registering officer: {e}")
            return jsonify({
                'success': False,
                'message': f'Error registering officer: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        logger.error(f"Error in register_officer: {e}")
        return jsonify({
            'success': False,
            'message': f'Error registering officer: {str(e)}'
        }), 500
    
@app.route('/api/officers/login', methods=['POST'])
def login_officer():
    try:
        data = request.get_json()
        
        if not data or not data.get('serviceNumber'):
            return jsonify({
                'success': False,
                'message': 'Service number is required'
            }), 400
        
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor(dictionary=True)
        
        try:
            cursor.execute('SELECT id, name, phone, service_number FROM officers WHERE service_number = %s', (data['serviceNumber'],))
            officer = cursor.fetchone()
            
            if not officer:
                return jsonify({
                    'success': False,
                    'message': 'Officer not found with this service number'
                }), 404
            
            # For officers, we'll just return their data (no JWT token for now)
            return jsonify({
                'success': True,
                'message': 'Login successful',
                'officer': {
                    'id': officer['id'],
                    'name': officer['name'],
                    'phone': officer['phone'],
                    'serviceNumber': officer['service_number']
                }
            }), 200
            
        except Exception as e:
            logger.error(f"Error in officer login: {e}")
            return jsonify({
                'success': False,
                'message': f'Error: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        logger.error(f"Error in login_officer: {e}")
        return jsonify({
            'success': False,
            'message': f'Error: {str(e)}'
        }), 500

@app.route('/api/system/health', methods=['GET'])
def system_health():
    """System health endpoint that returns application and database status."""
    try:
        # Check database connection
        conn = get_db_connection()
        db_status = "online" if conn else "offline"
        if conn:
            conn.close()
        
        # Get basic system metrics
        system_metrics = {
            "uptime": str(datetime.now(timezone.utc) - app_start_time),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        return jsonify({
            "success": True,
            "status": "healthy",
            "database": db_status,
            "system": system_metrics
        }), 200
        
    except Exception as e:
        logger.error(f"Error in system health check: {e}")
        return jsonify({
            "success": False,
            "status": "unhealthy",
            "error": str(e)
        }), 500

@app.route('/api/system/backup', methods=['POST'])
@admin_token_required
def system_backup(current_admin):
    """Create a database backup (simplified version)."""
    try:
        # In a real implementation, this would use mysqldump or similar
        backup_id = str(uuid.uuid4())
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        return jsonify({
            "success": True,
            "message": "Backup initiated",
            "backup_id": backup_id,
            "filename": f"feims_backup_{timestamp}.sql"
        }), 200
        
    except Exception as e:
        logger.error(f"Error in system backup: {e}")
        return jsonify({
            "success": False,
            "message": f"Backup failed: {str(e)}"
        }), 500

@app.route('/api/decommissions/upload', methods=['POST'])
@token_required
def upload_decommission_evidence(current_user):
    """Upload evidence for decommissioned items."""
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'message': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'success': False, 'message': 'No file selected'}), 400
        
        if file and allowed_file(file.filename):
            filename = secure_filename(f"{current_user['id']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{file.filename}")
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            
            try:
                file.save(filepath)
                return jsonify({
                    'success': True,
                    'message': 'File uploaded successfully',
                    'filepath': filename
                }), 200
            except Exception as e:
                logger.error(f"Error saving file: {e}")
                return jsonify({'success': False, 'message': f'Error saving file: {str(e)}'}), 500
        else:
            return jsonify({'success': False, 'message': 'File type not allowed'}), 400
            
    except Exception as e:
        logger.error(f"Error uploading file: {e}")
        return jsonify({'success': False, 'message': f'Error uploading file: {str(e)}'}), 500

@app.route('/uploads/decommissions/<filename>', methods=['GET'])
def get_decommission_evidence(filename):
    """Serve uploaded decommission evidence files."""
    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    except FileNotFoundError:
        return jsonify({'success': False, 'message': 'File not found'}), 404

@app.route('/api/vendor/dashboard', methods=['GET'])
@token_required
def vendor_dashboard(current_user):
    """Get dashboard statistics for a vendor."""
    try:
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor(dictionary=True)
        
        try:
            # Get QR code counts by status
            cursor.execute('SELECT status, COUNT(*) as count FROM qr_codes WHERE vendor_id = %s GROUP BY status', (current_user['id'],))
            qr_counts = {row['status']: row['count'] for row in cursor.fetchall()}
            
            # Get total sales amount
            cursor.execute('SELECT COALESCE(SUM(amount), 0) as total_sales FROM sales WHERE vendor_id = %s', (current_user['id'],))
            total_sales = cursor.fetchone()['total_sales']
            
            # Get service counts
            cursor.execute('SELECT COUNT(*) as service_count FROM services WHERE vendor_id = %s', (current_user['id'],))
            service_count = cursor.fetchone()['service_count']
            
            # Get recent QR codes
            cursor.execute('''
                SELECT id, product_type, size, type, status, created_at 
                FROM qr_codes 
                WHERE vendor_id = %s 
                ORDER BY created_at DESC 
                LIMIT 5
            ''', (current_user['id'],))
            recent_qr_codes = cursor.fetchall()
            
            return jsonify({
                'success': True,
                'stats': {
                    'qrCodes': {
                        'total': sum(qr_counts.values()),
                        'active': qr_counts.get('active', 0),
                        'inactive': qr_counts.get('inactive', 0),
                        'pending': qr_counts.get('pending', 0)
                    },
                    'totalSales': float(total_sales),
                    'serviceCount': service_count
                },
                'recentQrCodes': recent_qr_codes
            }), 200
            
        except Exception as e:
            logger.error(f"Error fetching dashboard data: {e}")
            return jsonify({
                'success': False,
                'message': f'Error fetching dashboard data: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        logger.error(f"Error in vendor_dashboard: {e}")
        return jsonify({
            'success': False,
            'message': f'Error fetching dashboard data: {str(e)}'
        }), 500

@app.route('/api/admin/vendors/<vendor_id>', methods=['GET'])
@admin_token_required
def admin_get_vendor_detail(current_admin, vendor_id):
    """Get detailed information about a specific vendor."""
    try:
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor(dictionary=True)
        
        try:
            # Get vendor details
            cursor.execute('''
                SELECT id, contact_name, email, phone, business_address, state, 
                       local_government, category, status, created_at
                FROM vendors 
                WHERE id = %s
            ''', (vendor_id,))
            
            vendor = cursor.fetchone()
            
            if not vendor:
                return jsonify({'success': False, 'message': 'Vendor not found'}), 404
            
            # Get vendor statistics
            cursor.execute('SELECT COUNT(*) as qr_count FROM qr_codes WHERE vendor_id = %s', (vendor_id,))
            qr_count = cursor.fetchone()['qr_count']
            
            cursor.execute('SELECT COUNT(*) as sales_count FROM sales WHERE vendor_id = %s', (vendor_id,))
            sales_count = cursor.fetchone()['sales_count']
            
            cursor.execute('SELECT COALESCE(SUM(amount), 0) as total_sales FROM sales WHERE vendor_id = %s', (vendor_id,))
            total_sales = cursor.fetchone()['total_sales']
            
            return jsonify({
                'success': True,
                'vendor': vendor,
                'stats': {
                    'qrCodes': qr_count,
                    'salesCount': sales_count,
                    'totalSales': float(total_sales)
                }
            }), 200
            
        except Exception as e:
            logger.error(f"Error fetching vendor details: {e}")
            return jsonify({
                'success': False,
                'message': f'Error fetching vendor details: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        logger.error(f"Error in admin_get_vendor_detail: {e}")
        return jsonify({
            'success': False,
            'message': f'Error fetching vendor details: {str(e)}'
        }), 500

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({
        'success': False,
        'message': 'Resource not found'
    }), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {error}")
    return jsonify({
        'success': False,
        'message': 'Internal server error'
    }), 500

@app.errorhandler(405)
def method_not_allowed(error):
    return jsonify({
        'success': False,
        'message': 'Method not allowed'
    }), 405

@app.route('/')
def index():
    """Root endpoint to verify the server is running"""
    return jsonify({
        'success': True,
        'message': 'FEIMS API Server is running',
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'version': '1.0.0'
    }), 200

# Initialize the database when the app starts
with app.app_context():
    init_db_pool()
    init_db()

if __name__ == '__main__':
    # Use Gunicorn compatible settings for production
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)