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
        
        # Create qr_code_requests table for pending QR code approvals
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS qr_code_requests (
                id VARCHAR(255) PRIMARY KEY,
                vendor_id VARCHAR(255) NOT NULL,
                product_type ENUM('existing_extinguisher', 'new_extinguisher', 'dcp_sachet') NOT NULL,
                size VARCHAR(10) NOT NULL,
                type VARCHAR(5) NOT NULL,
                quantity INT NOT NULL,
                data JSON NOT NULL,
                status ENUM('pending', 'approved', 'rejected') DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                FOREIGN KEY (vendor_id) REFERENCES vendors(id) ON DELETE CASCADE
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
            current_user = get_vendor_by_id(data['vendor_id'])
            
            if not current_user:
                return jsonify({'success': False, 'message': 'Vendor not found!'}), 401
                
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

@app.route('/api/vendor/request-qr', methods=['POST'])
@token_required
def request_qr_code(current_user):
    """Request QR code generation (requires admin approval)"""
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
            request_id = str(uuid.uuid4())
            
            # Store the request data
            cursor.execute('''
                INSERT INTO qr_code_requests 
                (id, vendor_id, product_type, size, type, quantity, data, status)
                VALUES (%s, %s, %s, %s, %s, %s, %s, 'pending')
            ''', (
                request_id,
                current_user['id'],
                data['productType'],
                data['size'],
                data['type'],
                quantity,
                json.dumps(data)
            ))
            
            conn.commit()
            
            return jsonify({
                'success': True,
                'message': 'QR code request submitted successfully. Awaiting admin approval.',
                'requestId': request_id
            }), 201
            
        except Exception as e:
            conn.rollback()
            logger.error(f"Error submitting QR code request: {e}")
            return jsonify({
                'success': False,
                'message': f'Error submitting QR code request: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        logger.error(f"Error in request_qr_code: {e}")
        return jsonify({
            'success': False,
            'message': f'Error submitting QR code request: {str(e)}'
        }), 500

@app.route('/api/admin/qr-requests', methods=['GET'])
@admin_token_required
def admin_get_qr_requests(current_admin):
    """Get all QR code requests for admin approval"""
    try:
        status = request.args.get('status', 'pending')
        
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor(dictionary=True)
        
        try:
            cursor.execute('''
                SELECT qr.id, qr.vendor_id, qr.product_type, qr.size, qr.type, qr.quantity, 
                       qr.data, qr.status, qr.created_at, qr.updated_at,
                       v.contact_name as vendor_name, v.email as vendor_email
                FROM qr_code_requests qr
                JOIN vendors v ON qr.vendor_id = v.id
                WHERE qr.status = %s
                ORDER BY qr.created_at DESC
            ''', (status,))
            
            requests = cursor.fetchall()
            
            return jsonify({
                'success': True,
                'requests': requests
            }), 200
            
        except Exception as e:
            logger.error(f"Error fetching QR code requests: {e}")
            return jsonify({
                'success': False,
                'message': f'Error fetching QR code requests: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        logger.error(f"Error in admin_get_qr_requests: {e}")
        return jsonify({
            'success': False,
            'message': f'Error fetching QR code requests: {str(e)}'
        }), 500

@app.route('/api/admin/qr-requests/<request_id>/approve', methods=['POST'])
@admin_token_required
def admin_approve_qr_request(current_admin, request_id):
    """Approve a QR code request and generate QR codes"""
    try:
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor(dictionary=True)
        
        try:
            # Get the request details
            cursor.execute('''
                SELECT id, vendor_id, product_type, size, type, quantity, data
                FROM qr_code_requests 
                WHERE id = %s AND status = 'pending'
            ''', (request_id,))
            
            request_data = cursor.fetchone()
            
            if not request_data:
                return jsonify({
                    'success': False,
                    'message': 'QR code request not found or already processed'
                }), 404
            
            # Parse the request data
            data = json.loads(request_data['data'])
            quantity = request_data['quantity']
            
            generated_codes = []
            
            for i in range(quantity):
                qr_id = str(uuid.uuid4())
                
                qr_data = {
                    'id': qr_id,
                    'vendor_id': request_data['vendor_id'],
                    'product_type': request_data['product_type'],
                    'size': request_data['size'],
                    'type': request_data['type'],
                    'generated_at': datetime.now().isoformat()
                }
                
                qr = qrcode.QRCode(
                    version=1,
                    error_correction=qrcode.constants.ERROR_CORRECT_L,
                    box_size=10,
                    border=4,
                )
                qr.add_data(json.dumps(qr_data))
                qr.make(fit=True)
                
                img = qr.make_image(fill_color="#ff7b00", back_color="white")
                
                buffered = io.BytesIO()
                img.save(buffered, format="PNG")
                img_str = base64.b64encode(buffered.getvalue()).decode()
                
                # Insert QR code
                cursor.execute('''
                    INSERT INTO qr_codes (id, vendor_id, product_type, size, type, qr_image, status)
                    VALUES (%s, %s, %s, %s, %s, %s, 'inactive')
                ''', (
                    qr_id,
                    request_data['vendor_id'],
                    request_data['product_type'],
                    request_data['size'],
                    request_data['type'],
                    img_str
                ))
                
                # Insert product details based on type
                if request_data['product_type'] == 'existing_extinguisher':
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
                    
                elif request_data['product_type'] == 'new_extinguisher':
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
                    
                elif request_data['product_type'] == 'dcp_sachet':
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
                    'product_type': request_data['product_type'],
                    'size': request_data['size'],
                    'type': request_data['type']
                })
            
            # Update request status to approved
            cursor.execute('''
                UPDATE qr_code_requests 
                SET status = 'approved', updated_at = NOW() 
                WHERE id = %s
            ''', (request_id,))
            
            conn.commit()
            
            return jsonify({
                'success': True,
                'message': f'QR code request approved. Generated {quantity} QR codes.',
                'generatedCodes': generated_codes
            }), 200
            
        except Exception as e:
            conn.rollback()
            logger.error(f"Error approving QR code request: {e}")
            return jsonify({
                'success': False,
                'message': f'Error approving QR code request: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        logger.error(f"Error in admin_approve_qr_request: {e}")
        return jsonify({
            'success': False,
            'message': f'Error approving QR code request: {str(e)}'
        }), 500

@app.route('/api/admin/qr-requests/<request_id>/reject', methods=['POST'])
@admin_token_required
def admin_reject_qr_request(current_admin, request_id):
    """Reject a QR code request"""
    try:
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                UPDATE qr_code_requests 
                SET status = 'rejected', updated_at = NOW() 
                WHERE id = %s AND status = 'pending'
            ''', (request_id,))
            
            if cursor.rowcount == 0:
                return jsonify({
                    'success': False,
                    'message': 'QR code request not found or already processed'
                }), 404
            
            conn.commit()
            
            return jsonify({
                'success': True,
                'message': 'QR code request rejected successfully'
            }), 200
            
        except Exception as e:
            conn.rollback()
            logger.error(f"Error rejecting QR code request: {e}")
            return jsonify({
                'success': False,
                'message': f'Error rejecting QR code request: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        logger.error(f"Error in admin_reject_qr_request: {e}")
        return jsonify({
            'success': False,
            'message': f'Error rejecting QR code request: {str(e)}'
        }), 500

@app.route('/api/vendor/qr-codes', methods=['GET'])
@token_required
def get_vendor_qr_codes(current_user):
    """Get all QR codes for a vendor"""
    try:
        status = request.args.get('status', None)
        
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor(dictionary=True)
        
        try:
            query = '''
                SELECT id, product_type, size, type, qr_image, status, created_at, activated_at
                FROM qr_codes 
                WHERE vendor_id = %s
            '''
            params = [current_user['id']]
            
            if status:
                query += ' AND status = %s'
                params.append(status)
            
            query += ' ORDER BY created_at DESC'
            
            cursor.execute(query, params)
            qr_codes = cursor.fetchall()
            
            return jsonify({
                'success': True,
                'qr_codes': qr_codes
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
    """Activate a QR code (make it active)"""
    try:
        data = request.get_json()
        
        if not data or 'qrId' not in data:
            return jsonify({
                'success': False,
                'message': 'QR code ID is required'
            }), 400
        
        qr_id = data['qrId']
        
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                UPDATE qr_codes 
                SET status = 'active', activated_at = NOW() 
                WHERE id = %s AND vendor_id = %s AND status = 'inactive'
            ''', (qr_id, current_user['id']))
            
            if cursor.rowcount == 0:
                return jsonify({
                    'success': False,
                    'message': 'QR code not found, already activated, or you do not have permission'
                }), 404
            
            conn.commit()
            
            return jsonify({
                'success': True,
                'message': 'QR code activated successfully'
            }), 200
            
        except Exception as e:
            conn.rollback()
            logger.error(f"Error activating QR code: {e}")
            return jsonify({
                'success': False,
                'message': f'Error activating QR code: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        logger.error(f"Error in activate_qr_code: {e}")
        return jsonify({
            'success': False,
            'message': f'Error activating QR code: {str(e)}'
        }), 500

@app.route('/api/scan/<qr_id>', methods=['GET'])
def verify_qr(qr_id):
    """Verify QR code (public endpoint)"""
    try:
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor(dictionary=True)
        
        try:
            # Get QR code details
            cursor.execute('''
                SELECT id, vendor_id, product_type, size, type, status, created_at, activated_at
                FROM qr_codes 
                WHERE id = %s
            ''', (qr_id,))
            
            qr_code = cursor.fetchone()
            
            if not qr_code:
                return jsonify({
                    'success': False,
                    'message': 'QR code not found'
                }), 404
            
            if qr_code['status'] != 'active':
                return jsonify({
                    'success': False,
                    'message': 'QR code is not active'
                }), 400
            
            # Get product details based on type
            product_data = None
            
            if qr_code['product_type'] == 'existing_extinguisher':
                cursor.execute('''
                    SELECT plate_number, building_address, manufacturing_date, expiry_date, 
                           engraved_id, phone_number, manufacturer_name, state, local_government
                    FROM existing_extinguishers 
                    WHERE qr_code_id = %s
                ''', (qr_id,))
                product_data = cursor.fetchone()
                
            elif qr_code['product_type'] == 'new_extinguisher':
                cursor.execute('''
                    SELECT manufacturer_name, son_number, ncs_receipt_number, ffs_fat_id, 
                           distributor_name, manufacturing_date, expiry_date, engraved_id, 
                           phone_number, state, local_government
                    FROM new_extinguishers 
                    WHERE qr_code_id = %s
                ''', (qr_id,))
                product_data = cursor.fetchone()
                
            elif qr_code['product_type'] == 'dcp_sachet':
                cursor.execute('''
                    SELECT manufacturer_name, son_number, ncs_receipt_number, ffs_fat_id, 
                           distributor_name, packaging_company, manufacturing_date, expiry_date, 
                           batch_lot_id, phone_number, state, local_government
                    FROM dcp_sachets 
                    WHERE qr_code_id = %s
                ''', (qr_id,))
                product_data = cursor.fetchone()
            
            # Get vendor details
            cursor.execute('''
                SELECT contact_name, email, phone, business_address, state, local_government, category
                FROM vendors 
                WHERE id = %s
            ''', (qr_code['vendor_id'],))
            
            vendor = cursor.fetchone()
            
            response_data = {
                'success': True,
                'qr_code': qr_code,
                'product_data': product_data,
                'vendor': vendor
            }
            
            return jsonify(response_data), 200
            
        except Exception as e:
            logger.error(f"Error verifying QR code: {e}")
            return jsonify({
                'success': False,
                'message': f'Error verifying QR code: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        logger.error(f"Error in verify_qr: {e}")
        return jsonify({
            'success': False,
            'message': f'Error verifying QR code: {str(e)}'
        }), 500

@app.route('/api/officers', methods=['POST'])
def officer_register():
    """Register a new officer (public endpoint)"""
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
        
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor()
        
        try:
            officer_id = str(uuid.uuid4())
            
            cursor.execute('''
                INSERT INTO officers (id, name, phone, service_number)
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
            
        except mysql.connector.Error as err:
            conn.rollback()
            if err.errno == 1062:  # Duplicate entry
                return jsonify({
                    'success': False,
                    'message': 'Officer with this service number already exists'
                }), 409
            logger.error(f"Database error in officer registration: {err}")
            return jsonify({
                'success': False,
                'message': f'Database error: {err}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        logger.error(f"Error in officer_register: {e}")
        return jsonify({
            'success': False,
            'message': f'Error: {str(e)}'
        }), 500

@app.route('/api/mobile/entry', methods=['POST'])
def officer_capture():
    """Capture data from mobile app (public endpoint)"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'success': False, 'message': 'No data provided'}), 400
        
        if 'productType' not in data or 'data' not in data:
            return jsonify({
                'success': False,
                'message': 'productType and data are required'
            }), 400
        
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor()
        
        try:
            entry_id = str(uuid.uuid4())
            
            cursor.execute('''
                INSERT INTO mobile_entries (id, product_type, data)
                VALUES (%s, %s, %s)
            ''', (
                entry_id,
                data['productType'],
                json.dumps(data['data'])
            ))
            
            conn.commit()
            
            return jsonify({
                'success': True,
                'message': 'Data captured successfully',
                'entryId': entry_id
            }), 201
            
        except Exception as e:
            conn.rollback()
            logger.error(f"Error capturing mobile data: {e}")
            return jsonify({
                'success': False,
                'message': f'Error capturing data: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        logger.error(f"Error in officer_capture: {e}")
        return jsonify({
            'success': False,
            'message': f'Error capturing data: {str(e)}'
        }), 500

@app.route('/api/vendor/entries', methods=['POST'])
@token_required
def vendor_capture(current_user):
    """Capture data from vendor (requires authentication)"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'success': False, 'message': 'No data provided'}), 400
        
        if 'productType' not in data or 'data' not in data:
            return jsonify({
                'success': False,
                'message': 'productType and data are required'
            }), 400
        
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor()
        
        try:
            entry_id = str(uuid.uuid4())
            
            cursor.execute('''
                INSERT INTO vendor_entries (id, vendor_id, product_type, data)
                VALUES (%s, %s, %s, %s)
            ''', (
                entry_id,
                current_user['id'],
                data['productType'],
                json.dumps(data['data'])
            ))
            
            conn.commit()
            
            return jsonify({
                'success': True,
                'message': 'Data captured successfully',
                'entryId': entry_id
            }), 201
            
        except Exception as e:
            conn.rollback()
            logger.error(f"Error capturing vendor data: {e}")
            return jsonify({
                'success': False,
                'message': f'Error capturing data: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        logger.error(f"Error in vendor_capture: {e}")
        return jsonify({
            'success': False,
            'message': f'Error capturing data: {str(e)}'
        }), 500

@app.route('/api/vendor/sales', methods=['POST'])
@token_required
def vendor_sales(current_user):
    """Record a sale (requires authentication)"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'success': False, 'message': 'No data provided'}), 400
        
        required_fields = ['productType', 'amount', 'customerName', 'customerPhone', 'paymentMethod']
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({
                    'success': False,
                    'message': f'{field} is required'
                }), 400
        
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor()
        
        try:
            sale_id = str(uuid.uuid4())
            
            cursor.execute('''
                INSERT INTO sales 
                (id, vendor_id, product_type, quantity, amount, customer_name, 
                 customer_phone, customer_email, customer_address, payment_method)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ''', (
                sale_id,
                current_user['id'],
                data['productType'],
                data.get('quantity', 1),
                data['amount'],
                data['customerName'],
                data['customerPhone'],
                data.get('customerEmail'),
                data.get('customerAddress'),
                data['paymentMethod']
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
        logger.error(f"Error in vendor_sales: {e}")
        return jsonify({
            'success': False,
            'message': f'Error recording sale: {str(e)}'
        }), 500

@app.route('/api/mobile/register', methods=['POST'])
def training_book():
    """Book a training session (public endpoint)"""
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
        
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor()
        
        try:
            booking_id = str(uuid.uuid4())
            
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
                'message': 'Training booked successfully',
                'bookingId': booking_id
            }), 201
            
        except Exception as e:
            conn.rollback()
            logger.error(f"Error booking training: {e}")
            return jsonify({
                'success': False,
                'message': f'Error booking training: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        logger.error(f"Error in training_book: {e}")
        return jsonify({
            'success': False,
            'message': f'Error booking training: {str(e)}'
        }), 500

@app.route('/api/mobile/entry', methods=['POST'])
def capture_data():
    """Capture data from mobile (public endpoint)"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'success': False, 'message': 'No data provided'}), 400
        
        if 'productType' not in data or 'data' not in data:
            return jsonify({
                'success': False,
                'message': 'productType and data are required'
            }), 400
        
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor()
        
        try:
            entry_id = str(uuid.uuid4())
            
            cursor.execute('''
                INSERT INTO mobile_entries (id, product_type, data)
                VALUES (%s, %s, %s)
            ''', (
                entry_id,
                data['productType'],
                json.dumps(data['data'])
            ))
            
            conn.commit()
            
            return jsonify({
                'success': True,
                'message': 'Data captured successfully',
                'entryId': entry_id
            }), 201
            
        except Exception as e:
            conn.rollback()
            logger.error(f"Error capturing mobile data: {e}")
            return jsonify({
                'success': False,
                'message': f'Error capturing data: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        logger.error(f"Error in capture_data: {e}")
        return jsonify({
            'success': False,
            'message': f'Error capturing data: {str(e)}'
        }), 500

@app.route('/api/admin/login', methods=['POST'])
def admin_login():
    """Admin login endpoint"""
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
                'message': 'Invalid username or password'
            }), 401
        
        token = jwt.encode({
            'username': data['username'],
            'role': 'admin',
            'exp': datetime.now(timezone.utc) + timedelta(hours=8)
        }, app.config['SECRET_KEY'], algorithm="HS256")
        
        return jsonify({
            'success': True,
            'message': 'Login successful',
            'token': token
        }), 200
        
    except Exception as e:
        logger.error(f"Error in admin login: {e}")
        return jsonify({
            'success': False,
            'message': f'Error: {str(e)}'
        }), 500

@app.route('/api/admin/vendors', methods=['GET'])
@admin_token_required
def admin_get_vendors(current_admin):
    """Get all vendors for admin"""
    try:
        status = request.args.get('status', None)
        
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor(dictionary=True)
        
        try:
            query = '''
                SELECT id, contact_name, email, phone, business_address, state, 
                       local_government, category, status, created_at
                FROM vendors
            '''
            params = []
            
            if status:
                query += ' WHERE status = %s'
                params.append(status)
            
            query += ' ORDER BY created_at DESC'
            
            cursor.execute(query, params)
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
    """Approve a vendor"""
    try:
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                UPDATE vendors 
                SET status = 'approved'
                WHERE id = %s
            ''', (vendor_id,))
            
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
    """Reject a vendor"""
    try:
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                UPDATE vendors 
                SET status = 'rejected'
                WHERE id = %s
            ''', (vendor_id,))
            
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

@app.route('/api/admin/stats', methods=['GET'])
@admin_token_required
def admin_stats(current_admin):
    """Get admin dashboard statistics"""
    try:
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor(dictionary=True)
        
        try:
            # Get vendor counts by status
            cursor.execute('''
                SELECT status, COUNT(*) as count 
                FROM vendors 
                GROUP BY status
            ''')
            vendor_counts = cursor.fetchall()
            
            # Get QR code counts by status
            cursor.execute('''
                SELECT status, COUNT(*) as count 
                FROM qr_codes 
                GROUP BY status
            ''')
            qr_counts = cursor.fetchall()
            
            # Get QR code requests by status
            cursor.execute('''
                SELECT status, COUNT(*) as count 
                FROM qr_code_requests 
                GROUP BY status
            ''')
            request_counts = cursor.fetchall()
            
            # Get recent sales total
            cursor.execute('''
                SELECT COUNT(*) as count, COALESCE(SUM(amount), 0) as total 
                FROM sales 
                WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
            ''')
            sales_data = cursor.fetchone()
            
            # Get recent training bookings
            cursor.execute('''
                SELECT COUNT(*) as count 
                FROM training_bookings 
                WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
            ''')
            training_data = cursor.fetchone()
            
            stats = {
                'vendors': vendor_counts,
                'qr_codes': qr_counts,
                'qr_requests': request_counts,
                'recent_sales': sales_data,
                'recent_training': training_data
            }
            
            return jsonify({
                'success': True,
                'stats': stats
            }), 200
            
        except Exception as e:
            logger.error(f"Error fetching admin stats: {e}")
            return jsonify({
                'success': False,
                'message': f'Error fetching stats: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        logger.error(f"Error in admin_stats: {e}")
        return jsonify({
            'success': False,
            'message': f'Error fetching stats: {str(e)}'
        }), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    try:
        # Check database connection
        conn = get_db_connection()
        if conn is None:
            return jsonify({
                'success': False,
                'message': 'Database connection failed',
                'status': 'unhealthy'
            }), 500
        
        conn.close()
        
        uptime = datetime.now(timezone.utc) - app_start_time
        
        return jsonify({
            'success': True,
            'message': 'Service is healthy',
            'status': 'healthy',
            'uptime': str(uptime),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }), 200
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({
            'success': False,
            'message': f'Health check failed: {str(e)}',
            'status': 'unhealthy'
        }), 500

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({
        'success': False,
        'message': 'Endpoint not found'
    }), 404

@app.errorhandler(405)
def method_not_allowed(error):
    return jsonify({
        'success': False,
        'message': 'Method not allowed'
    }), 405

@app.errorhandler(500)
def internal_server_error(error):
    logger.error(f"Internal server error: {error}")
    return jsonify({
        'success': False,
        'message': 'Internal server error'
    }), 500

if __name__ == '__main__':
    # Initialize database
    init_db()
    
    # Start the Flask application
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    
    app.run(host='0.0.0.0', port=port, debug=debug)