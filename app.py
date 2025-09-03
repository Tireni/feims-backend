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
from datetime import datetime
import json  # Add this import

try:
    import psutil  # For system metrics
except ImportError:
    psutil = None  # psutil may not be available in some environments

# -----------------------------------------------------------------------------
# Application start time for uptime calculations
#
# Capture the time the application started. This value is used by the
# `/api/system/monitoring` endpoint to calculate the uptime percentage and
# human‑readable uptime string. Uptime is reported as the fraction of time
# since startup relative to a 30‑day window, matching the specification that
# calls for an uptime like "99.9%" over the last 30 days. If the app has been
app_start_time = datetime.now(timezone.utc)

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Secret key for JWT
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'feims-secret-key-2025'

# -----------------------------------------------------------------------------
# Admin configuration
#
# For the purposes of the FEIMS prototype the administrator credentials are
# stored in environment variables. In a production environment these values
# should be stored securely (e.g. in a secrets manager) and rotated
# regularly. The admin login endpoint defined later uses these values to
# authenticate the administrator and issues a JWT token containing the
# username and a role of "admin".

# Default administrator username and password.  These can be overridden by
# setting the environment variables ADMIN_USERNAME and ADMIN_PASSWORD when
# running the application.  The password is not hashed here because this
# prototype is intended for demonstration.  In a real deployment store and
# verify hashed passwords (e.g. using bcrypt).
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'adminpass')

def admin_token_required(f):
    """Decorator that ensures the caller is an authenticated administrator.

    The decorator checks for a JWT token in the Authorization header.  It
    expects the token to contain a `role` field set to "admin".  If the
    token is missing, invalid or the role is not "admin" the request is
    rejected.  If the token is valid the decoded admin details are passed
    as the first argument to the wrapped function.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization')
        if auth_header:
            # Accept tokens passed as "Bearer <token>" or just the token
            parts = auth_header.split()
            token = parts[-1]
        if not token:
            return jsonify({'success': False, 'message': 'Admin token is missing'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            if data.get('role') != 'admin':
                return jsonify({'success': False, 'message': 'Admin privileges required'}), 403
            current_admin = {'username': data.get('username')}
        except Exception:
            return jsonify({'success': False, 'message': 'Invalid or expired admin token'}), 401
        return f(current_admin, *args, **kwargs)
    return decorated

# -----------------------------------------------------------------------------
# File upload configuration for decommission evidence
#
# Decommission records may include a photo as evidence. Configure an upload
# directory and allowed extensions. Use the built‑in werkzeug `secure_filename`
# helper to generate safe filenames, and create the uploads directory on
# startup. See `allowed_file` below for extension checks.

# Directory where decommission evidence photos are stored relative to the
# application root. A subfolder ("uploads/decommissions") keeps evidence
# separate from other assets.
UPLOAD_FOLDER = 'uploads/decommissions'

# Allowed file extensions for uploaded evidence. Limiting the allowed types
# helps prevent users from uploading arbitrary files that could be executed.
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Expose the configured upload folder via Flask config. This allows other
# modules (and routes) to reference the upload path without hardcoding it.
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Create the upload directory if it does not already exist. Without this
# precaution an attempt to save a file would raise a `FileNotFoundError`.
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename: str) -> bool:
    """Check whether a filename has an allowed extension.

    This helper splits the filename on the last period to extract the
    extension and then compares it against the `ALLOWED_EXTENSIONS` set. The
    check is case‑insensitive to support common variations like `.JPG`.

    Args:
        filename: The original filename uploaded by the user.

    Returns:
        True if the extension is present and allowed; False otherwise.
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Database configuration
db_config = {
    'host': os.environ.get('MYSQLHOST', '95.85.5.9'),
    'user': os.environ.get('MYSQLUSER', 'ffsnfdrcnet_enoch'),
    'password': os.environ.get('MYSQLPASSWORD', 'Enoch@0330'),
    'database': os.environ.get('MYSQLDATABASE', 'ffsnfdrcnet_feimsdb'),
    'port': int(os.environ.get('MYSQLPORT', 3306))
}
def get_db_connection():
    try:
        return mysql.connector.connect(**db_config)
    except mysql.connector.Error as e:
        print(f"Database connection error: {e}")
        # Return None instead of crashing
        return None
# Create necessary tables if they don't exist
def init_db():
    conn = get_db_connection()
    if conn is None:
        print("Failed to connect to database. Skipping table creation.")
        return
    
    cursor = conn.cursor()
    
    # Create vendors table (existing)
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
    
    # Create vendor_documents table (existing)
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
    
    # Create qr_codes table with additional fields
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
            phone_number VARCHAR(20) NOT NULL,
            manufacturer_name VARCHAR(255) NOT NULL,
            state VARCHAR(100) NOT NULL,
            local_government VARCHAR(100) NOT NULL,
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

    # -------------------------------------------------------------------------
    # Additional tables for Payments, Training, Compliance and Messaging
    #
    # The FEIMS vendor dashboard has been expanded to include payments &
    # settlements, training and certification management, compliance audits,
    # vendor status tracking, notifications, messaging and reporting. The
    # following tables support those new features. See the corresponding
    # API endpoints below for details on how these tables are used.
    #
    # payments: records each POS transaction made by a vendor. The total
    # amount is split automatically amongst different stakeholders (manufacturer,
    # NFEC, aggregator, IGR and the vendor) and persisted alongside the
    # transaction for settlement history. Note that the shares are computed
    # when the payment is recorded via the API.
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

    # training_materials: stores the NFEC training modules available to vendors.
    # Each record includes a title, description and a URL to an external
    # resource (e.g. PDF, video or web page). These materials are read-only
    # from the vendor perspective.
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS training_materials (
            id VARCHAR(255) PRIMARY KEY,
            title VARCHAR(255) NOT NULL,
            description TEXT,
            url VARCHAR(500) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # certifications: tracks staff members submitted by a vendor for NFEC
    # certification. When a certification is created it is marked as
    # 'pending'. NFEC administrators can update the status to 'approved' or
    # 'rejected' via a separate admin dashboard (not implemented here).
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

    # compliance_audits: records compliance audits submitted by vendors. Each
    # audit contains the date of the audit, a description of the findings,
    # whether the audit passed or failed, and optional notes. This table
    # supports the compliance & training features of the dashboard.
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

    # notifications: stores automated and manual notifications sent to
    # vendors. Notifications can cover anomalies, complaints, compliance
    # breaches or general information. Vendors retrieve notifications via
    # the API and can mark them as read client-side. The table also stores
    # the category and creation timestamp.
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

    # messages: represents a simple chat between the vendor and NFEC/FFS
    # administrators. Each message stores who the sender is (vendor or
    # admin) and the content. Messages are ordered by timestamp.
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

    # reports: allows vendors to report incidents, suspicious vendors or
    # fraud. Each report contains a subject line, a description and a
    # category. Administrators can review these reports via an admin
    # interface.
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

    # -------------------------------------------------------------------------
    # Mobile application tables
    #
    # mobile_entries: captures extinguisher/DCP details submitted via the
    # public-facing mobile app. Each entry stores the product type and a
    # JSON document containing the submitted details. This table allows
    # citizens and field officers to log extinguisher data into the NFEC
    # repository without requiring vendor credentials.
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS mobile_entries (
            id VARCHAR(255) PRIMARY KEY,
            product_type ENUM('existing_extinguisher', 'new_extinguisher', 'dcp_sachet') NOT NULL,
            data JSON NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # training_bookings: records training bookings made through the mobile
    # application. Each booking stores contact details, the plate or address
    # used for identification and the desired training date and time. NFEC
    # administrators can later allocate slots and track completions.
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

    # mobile_payments: stores payments made by the general public via the
    # mobile app. These might include training kit purchases, refill
    # purchases or activations. Unlike vendor payments, these payments do
    # not include a vendor share. NFEC and other stakeholder shares are
    # computed on the fly when recording the payment.
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

    # ---------------------------------------------------------------------
    # Vendor entries table
    #
    # Vendors can capture extinguisher or DCP details via their dashboard.
    # These entries are stored separately from mobile entries so that
    # administrative users can distinguish between data submitted by the
    # general public and data submitted by vendors. Each record stores the
    # vendor's ID, the product type and the JSON data submitted. The
    # created_at timestamp allows for tracking when the capture occurred.
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

    conn.commit()
    cursor.close()
    conn.close()

    # Seed training materials if none exist. This provides some example
    # resources to vendors on first run. The check prevents duplicate
    # insertion if init_db() is called multiple times. Modify or extend
    # these entries as required.
    conn = get_db_connection()
    cursor = conn.cursor()
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
    cursor.close()
    conn.close()

# JWT token required decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        
        try:
            # Remove 'Bearer ' prefix if present
            if token.startswith('Bearer '):
                token = token[7:]
            
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = get_vendor_by_id(data['vendor_id'])
        except:
            return jsonify({'message': 'Token is invalid!'}), 401
        
        return f(current_user, *args, **kwargs)
    
    return decorated

# Helper function to get vendor by ID
def get_vendor_by_id(vendor_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    cursor.execute('SELECT id, contact_name, email, phone, business_address, state, local_government, category, status FROM vendors WHERE id = %s', (vendor_id,))
    vendor = cursor.fetchone()
    
    cursor.close()
    conn.close()
    
    return vendor

# Helper function to get vendor by email
def get_vendor_by_email(email):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    cursor.execute('SELECT id, contact_name, email, phone, password_hash, status FROM vendors WHERE email = %s', (email,))
    vendor = cursor.fetchone()
    
    cursor.close()
    conn.close()
    
    return vendor

@app.route('/api/vendors/register', methods=['POST'])
def register_vendor():
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['contactName', 'email', 'phone', 'businessAddress', 'state', 'localGovernment', 'category', 'password']
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({
                    'success': False,
                    'message': f'{field} is required'
                }), 400
        
        # Check if vendor already exists
        existing_vendor = get_vendor_by_email(data['email'])
        if existing_vendor:
            return jsonify({
                'success': False,
                'message': 'Vendor with this email already exists'
            }), 409
        
        # Generate unique ID for vendor
        vendor_id = str(uuid.uuid4())
        
        # Hash password
        password_hash = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        # Connect to database
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Insert vendor data
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
        cursor.close()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': 'Vendor registration submitted successfully. Awaiting approval.',
            'vendorId': vendor_id
        }), 201
        
    except mysql.connector.Error as err:
        return jsonify({
            'success': False,
            'message': f'Database error: {err}'
        }), 500
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error: {str(e)}'
        }), 400

@app.route('/api/vendors/login', methods=['POST'])
def login_vendor():
    try:
        data = request.get_json()
        
        # Validate required fields
        if not data or not data.get('email') or not data.get('password'):
            return jsonify({
                'success': False,
                'message': 'Email and password are required'
            }), 400
        
        # Get vendor by email
        vendor = get_vendor_by_email(data['email'])
        
        if not vendor:
            return jsonify({
                'success': False,
                'message': 'Invalid email or password'
            }), 401
        
        # Check password
        if not bcrypt.checkpw(data['password'].encode('utf-8'), vendor['password_hash'].encode('utf-8')):
            return jsonify({
                'success': False,
                'message': 'Invalid email or password'
            }), 401
        
        # Check if vendor is approved
        if vendor['status'] != 'approved':
            return jsonify({
                'success': False,
                'message': 'Your account is pending approval. Please contact administrator.'
            }), 403
        
        # Generate JWT token
        token = jwt.encode({
            'vendor_id': vendor['id'],
            'email': vendor['email']
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
        return jsonify({
            'success': False,
            'message': f'Error: {str(e)}'
        }), 500

@app.route('/api/vendors', methods=['GET'])
@token_required
def get_vendors(current_user):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute('SELECT id, contact_name, email, phone, business_address, state, local_government, category, status, created_at FROM vendors ORDER BY created_at DESC')
        vendors = cursor.fetchall()
        
        cursor.close()
        conn.close()
        
        return jsonify({
            'success': True,
            'vendors': vendors
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error: {str(e)}'
        }), 500

@app.route('/api/vendor/generate-qr', methods=['POST'])
@token_required
def generate_qr_code(current_user):
    try:
        data = request.get_json()
        
        # Validate required fields based on product type
        required_fields = ['productType', 'size', 'type', 'quantity']
        
        # Add product-specific required fields
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
        
        quantity = min(max(1, int(data['quantity'])), 100)  # Limit to 100 codes per request
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        generated_codes = []
        
        for i in range(quantity):
            # Generate unique QR code ID
            qr_id = str(uuid.uuid4())
            
            # Create QR code data
            qr_data = {
                'id': qr_id,
                'vendor_id': current_user['id'],
                'product_type': data['productType'],
                'size': data['size'],
                'type': data['type'],
                'generated_at': datetime.now().isoformat()
            }
            
            # Generate QR code image
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(json.dumps(qr_data))
            qr.make(fit=True)
            
            img = qr.make_image(fill_color="#ff7b00", back_color="white")
            
            # Convert image to base64
            buffered = io.BytesIO()
            img.save(buffered, format="PNG")
            img_str = base64.b64encode(buffered.getvalue()).decode()
            
            # Store QR code in database
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
            
            # Store product-specific data
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
                'qrImage': f"data:image/png;base64,{img_str}"
            })
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': f'Successfully generated {quantity} QR codes',
            'codes': generated_codes
        }), 201
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error generating QR codes: {str(e)}'
        }), 500

@app.route('/api/scan/<qr_id>', methods=['GET'])
def scan_qr_code(qr_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Get basic QR code information
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
        
        # Get product-specific information based on type
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
        
        cursor.close()
        conn.close()
        
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
        return jsonify({
            'success': False,
            'message': f'Error scanning QR code: {str(e)}'
        }), 500

@app.route('/api/vendor/qrcodes', methods=['GET'])
@token_required
def get_vendor_qr_codes(current_user):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute('''
            SELECT id, product_type, size, type, status, created_at, activated_at, qr_image
            FROM qr_codes 
            WHERE vendor_id = %s 
            ORDER BY created_at DESC
        ''', (current_user['id'],))
        
        qr_codes = cursor.fetchall()
        
        cursor.close()
        conn.close()
        
        return jsonify({
            'success': True,
            'qrCodes': qr_codes
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error fetching QR codes: {str(e)}'
        }), 500

@app.route('/api/vendor/activate-qr', methods=['POST'])
@token_required
def activate_qr_code(current_user):
    """
    Allow a vendor to request activation of a QR code.

    In the FEIMS workflow, a vendor cannot directly activate a QR code.  Codes
    remain inactive until reviewed and approved by an administrator.  When a
    vendor submits an activation request, the QR code status is set to
    ``pending`` and no activation timestamp is recorded.  Administrators can
    later approve the request via the admin dashboard, changing the status
    to ``active`` and setting the activation time.  This endpoint simply
    updates the status to ``pending`` to indicate that approval is required.
    """
    try:
        data = request.get_json() or {}
        qr_id = data.get('qrId')
        if not qr_id:
            return jsonify({'success': False, 'message': 'QR code ID is required'}), 400
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        # Check that the QR code exists and belongs to the current vendor
        cursor.execute('SELECT vendor_id, status FROM qr_codes WHERE id = %s', (qr_id,))
        record = cursor.fetchone()
        if not record:
            cursor.close(); conn.close()
            return jsonify({'success': False, 'message': 'QR code not found'}), 404
        if record['vendor_id'] != current_user['id']:
            cursor.close(); conn.close()
            return jsonify({'success': False, 'message': 'Unauthorized to request activation for this QR code'}), 403
        # Only allow activation requests if code is currently inactive
        if record['status'] == 'active':
            cursor.close(); conn.close()
            return jsonify({'success': False, 'message': 'QR code is already active'}), 400
        # Mark status as pending to indicate the activation request
        cursor.execute('UPDATE qr_codes SET status = %s WHERE id = %s', ('pending', qr_id))
        conn.commit()
        cursor.close(); conn.close()
        return jsonify({'success': True, 'message': 'Activation request submitted. Awaiting NFEC approval.'}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error submitting activation request: {str(e)}'}), 500

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
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE vendors SET status = %s WHERE id = %s
        ''', (data['status'], vendor_id))
        
        if cursor.rowcount == 0:
            return jsonify({
                'success': False,
                'message': 'Vendor not found'
            }), 404
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': f'Vendor status updated to {data["status"]}'
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error: {str(e)}'
        }), 500

@app.route('/api/vendor/sales', methods=['GET', 'POST'])
@token_required
def vendor_sales(current_user):
    if request.method == 'GET':
        try:
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)
            
            cursor.execute('''
                SELECT id, product_type, quantity, amount, customer_name, customer_phone, 
                       customer_email, customer_address, payment_method, created_at
                FROM sales 
                WHERE vendor_id = %s 
                ORDER BY created_at DESC
            ''', (current_user['id'],))
            
            sales = cursor.fetchall()
            
            cursor.close()
            conn.close()
            
            return jsonify({
                'success': True,
                'sales': sales
            }), 200
            
        except Exception as e:
            return jsonify({
                'success': False,
                'message': f'Error fetching sales records: {str(e)}'
            }), 500
    
    elif request.method == 'POST':
        try:
            data = request.get_json()
            
            # Validate required fields
            required_fields = ['productType', 'quantity', 'amount', 'customerName', 'customerPhone', 'paymentMethod']
            for field in required_fields:
                if field not in data or not data[field]:
                    return jsonify({
                        'success': False,
                        'message': f'{field} is required'
                    }), 400
            
            # Generate unique ID for sale
            sale_id = str(uuid.uuid4())
            
            # Connect to database
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # Insert sale data
            cursor.execute('''
                INSERT INTO sales (id, vendor_id, product_type, quantity, amount, 
                customer_name, customer_phone, customer_email, customer_address, payment_method)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ''', (
                sale_id,
                current_user['id'],
                data['productType'],
                data['quantity'],
                data['amount'],
                data['customerName'],
                data['customerPhone'],
                data.get('customerEmail', ''),
                data.get('customerAddress', ''),
                data['paymentMethod']
            ))
            
            conn.commit()
            cursor.close()
            conn.close()
            
            return jsonify({
                'success': True,
                'message': 'Sale recorded successfully',
                'saleId': sale_id
            }), 201
            
        except Exception as e:
            return jsonify({
                'success': False,
                'message': f'Error recording sale: {str(e)}'
            }), 500

@app.route('/api/vendor/services', methods=['GET', 'POST'])
@token_required
def vendor_services(current_user):
    if request.method == 'GET':
        try:
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)
            
            cursor.execute('''
                SELECT id, qr_code_id, service_type, description, amount, 
                       customer_name, customer_phone, customer_email, customer_address, created_at
                FROM services 
                WHERE vendor_id = %s 
                ORDER BY created_at DESC
            ''', (current_user['id'],))
            
            services = cursor.fetchall()
            
            cursor.close()
            conn.close()
            
            return jsonify({
                'success': True,
                'services': services
            }), 200
            
        except Exception as e:
            return jsonify({
                'success': False,
                'message': f'Error fetching service records: {str(e)}'
            }), 500
    
    elif request.method == 'POST':
        try:
            data = request.get_json()
            
            # Validate required fields
            required_fields = ['qrCodeId', 'serviceType']
            for field in required_fields:
                if field not in data or not data[field]:
                    return jsonify({
                        'success': False,
                        'message': f'{field} is required'
                    }), 400
            
            # Generate unique ID for service
            service_id = str(uuid.uuid4())
            
            # Connect to database
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # Insert service data
            cursor.execute('''
                INSERT INTO services (id, vendor_id, qr_code_id, service_type, description, 
                amount, customer_name, customer_phone, customer_email, customer_address)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ''', (
                service_id,
                current_user['id'],
                data['qrCodeId'],
                data['serviceType'],
                data.get('description', ''),
                data.get('amount', 0),
                data.get('customerName', ''),
                data.get('customerPhone', ''),
                data.get('customerEmail', ''),
                data.get('customerAddress', '')
            ))
            
            conn.commit()
            cursor.close()
            conn.close()
            
            return jsonify({
                'success': True,
                'message': 'Service recorded successfully',
                'serviceId': service_id
            }), 201
            
        except Exception as e:
            return jsonify({
                'success': False,
                'message': f'Error recording service: {str(e)}'
            }), 500

@app.route('/api/vendor/decommissions', methods=['GET', 'POST'])
@token_required
def vendor_decommissions(current_user):
    if request.method == 'GET':
        try:
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)
            
            cursor.execute('''
                SELECT id, qr_code_id, reason, disposal_method, disposal_date, 
                       notes, evidence_path, created_at
                FROM decommissions 
                WHERE vendor_id = %s 
                ORDER BY created_at DESC
            ''', (current_user['id'],))
            
            decommissions = cursor.fetchall()
            
            cursor.close()
            conn.close()
            
            return jsonify({
                'success': True,
                'decommissions': decommissions
            }), 200
            
        except Exception as e:
            return jsonify({
                'success': False,
                'message': f'Error fetching decommission records: {str(e)}'
            }), 500
    
    elif request.method == 'POST':
        try:
            # -----------------------------------------------------------------
            # Read and validate the submitted form fields. Decommission records
            # require a QR code ID, a reason, a disposal method and a date.
            # Additional notes are optional. Missing any required field
            # immediately returns an error to the client.
            qr_code_id = request.form.get('qrCodeId')
            reason = request.form.get('reason')
            disposal_method = request.form.get('disposalMethod')
            disposal_date = request.form.get('disposalDate')
            notes = request.form.get('notes', '')
            
            if not all([qr_code_id, reason, disposal_method, disposal_date]):
                return jsonify({
                    'success': False,
                    'message': 'Missing required fields'
                }), 400

            # Generate a unique ID for the new decommission record.
            decommission_id = str(uuid.uuid4())

            # -----------------------------------------------------------------
            # Handle evidence file upload. We only accept files with allowed
            # extensions and use werkzeug's secure_filename to avoid directory
            # traversal attacks. Files are saved into the configured
            # UPLOAD_FOLDER, and the resulting relative path is persisted
            # alongside the record. If no evidence is provided, the path
            # remains None.
            evidence_path = None
            if 'evidence' in request.files:
                evidence_file = request.files['evidence']
                if (evidence_file and evidence_file.filename and
                    allowed_file(evidence_file.filename)):
                    # Compose a new filename using the decommission ID to
                    # guarantee uniqueness and preserve the original extension.
                    filename = f"{decommission_id}_{secure_filename(evidence_file.filename)}"
                    evidence_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    # Save the file to the upload directory.
                    evidence_file.save(evidence_path)

            # -----------------------------------------------------------------
            # Insert the new decommission record into the database. We always
            # record the vendor ID from the authenticated user along with the
            # details supplied in the form. The evidence path can be None.
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO decommissions (id, vendor_id, qr_code_id, reason,
                disposal_method, disposal_date, notes, evidence_path)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            ''', (
                decommission_id,
                current_user['id'],
                qr_code_id,
                reason,
                disposal_method,
                disposal_date,
                notes,
                evidence_path
            ))
            
            # Deactivate the associated QR code since it has been decommissioned.
            cursor.execute('''
                UPDATE qr_codes 
                SET status = 'inactive'
                WHERE id = %s
            ''', (qr_code_id,))

            conn.commit()
            cursor.close()
            conn.close()

            return jsonify({
                'success': True,
                'message': 'Decommission recorded successfully',
                'decommissionId': decommission_id
            }), 201

        except Exception as e:
            # Ensure we return a generic error message if anything unexpected
            # happens during processing, while logging the specific exception
            # message for debugging purposes.
            return jsonify({
                'success': False,
                'message': f'Error recording decommission: {str(e)}'
            }), 500

@app.route('/api/vendor/analytics', methods=['GET'])
@token_required
def vendor_analytics(current_user):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Get sales summary
        cursor.execute('''
            SELECT 
                COUNT(*) as total_sales,
                SUM(amount) as total_revenue,
                AVG(amount) as avg_transaction
            FROM sales 
            WHERE vendor_id = %s
        ''', (current_user['id'],))
        
        sales_summary = cursor.fetchone()
        
        # Get monthly sales
        cursor.execute('''
            SELECT 
                SUM(amount) as monthly_sales
            FROM sales 
            WHERE vendor_id = %s 
            AND MONTH(created_at) = MONTH(CURRENT_DATE())
            AND YEAR(created_at) = YEAR(CURRENT_DATE())
        ''', (current_user['id'],))
        
        monthly_sales = cursor.fetchone()
        
        # Get service summary
        cursor.execute('''
            SELECT 
                COUNT(*) as total_services
            FROM services 
            WHERE vendor_id = %s
        ''', (current_user['id'],))
        
        service_summary = cursor.fetchone()
        
        # Get monthly services
        cursor.execute('''
            SELECT 
                COUNT(*) as monthly_services
            FROM services 
            WHERE vendor_id = %s 
            AND MONTH(created_at) = MONTH(CURRENT_DATE())
            AND YEAR(created_at) = YEAR(CURRENT_DATE())
        ''', (current_user['id'],))
        
        monthly_services = cursor.fetchone()
        
        # Get product distribution
        cursor.execute('''
            SELECT 
                product_type,
                COUNT(*) as count,
                ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM sales WHERE vendor_id = %s), 2) as percentage
            FROM sales 
            WHERE vendor_id = %s
            GROUP BY product_type
        ''', (current_user['id'], current_user['id']))
        
        product_distribution = cursor.fetchall()
        
        # Get monthly sales trends (last 6 months)
        cursor.execute('''
            SELECT 
                DATE_FORMAT(created_at, '%Y-%m') as month,
                COUNT(*) as sales_count,
                COALESCE(SUM(amount), 0) as sales_amount
            FROM sales 
            WHERE vendor_id = %s 
                AND created_at >= DATE_SUB(NOW(), INTERVAL 6 MONTH)
            GROUP BY DATE_FORMAT(created_at, '%Y-%m')
            ORDER BY month
        ''', (current_user['id'],))
        sales_trends = {row['month']: {'sales_count': row['sales_count'], 'sales_amount': float(row['sales_amount'])} for row in cursor.fetchall()}

        # Get monthly service trends (last 6 months)
        cursor.execute('''
            SELECT 
                DATE_FORMAT(created_at, '%Y-%m') as month,
                COUNT(*) as service_count
            FROM services
            WHERE vendor_id = %s
                AND created_at >= DATE_SUB(NOW(), INTERVAL 6 MONTH)
            GROUP BY DATE_FORMAT(created_at, '%Y-%m')
            ORDER BY month
        ''', (current_user['id'],))
        service_trends = {row['month']: row['service_count'] for row in cursor.fetchall()}

        # Build combined monthly trends data. We include sales_count, sales_amount and service_count for each month
        # present in either sales_trends or service_trends. Sorting ensures chronological order.
        all_months = sorted(set(list(sales_trends.keys()) + list(service_trends.keys())))
        monthly_trends = []
        for month in all_months:
            sales_data = sales_trends.get(month, {'sales_count': 0, 'sales_amount': 0.0})
            service_count = service_trends.get(month, 0)
            monthly_trends.append({
                'month': month,
                'sales_count': sales_data['sales_count'],
                'sales_amount': sales_data['sales_amount'],
                'service_count': service_count
            })

        cursor.close()
        conn.close()

        analytics_data = {
            'salesSummary': {
                'totalSales': sales_summary['total_sales'] if sales_summary else 0,
                'totalRevenue': float(sales_summary['total_revenue']) if sales_summary and sales_summary['total_revenue'] else 0,
                'averageTransaction': float(sales_summary['avg_transaction']) if sales_summary and sales_summary['avg_transaction'] else 0,
                'monthlySales': float(monthly_sales['monthly_sales']) if monthly_sales and monthly_sales['monthly_sales'] else 0
            },
            'serviceSummary': {
                'totalServices': service_summary['total_services'] if service_summary else 0,
                'monthlyServices': monthly_services['monthly_services'] if monthly_services else 0
            },
            'productDistribution': [
                {
                    'name': item['product_type'],
                    'count': item['count'],
                    'percentage': float(item['percentage']) if item['percentage'] else 0
                } for item in product_distribution
            ],
            'monthlyTrends': monthly_trends
        }

        return jsonify({
            'success': True,
            'analytics': analytics_data
        }), 200
    except Exception as e:
        # In case of any error (e.g. database failure), return an error
        # response rather than allowing an uncaught exception to break
        # Flask routing. The error message is included for debugging.
        return jsonify({
            'success': False,
            'message': f'Error fetching analytics: {str(e)}'
        }), 500


# -----------------------------------------------------------------------------
# System monitoring endpoint
#
# Returns current application performance and health metrics. These values are
# intended for display on a real‑time dashboard and include CPU and memory
# utilisation, network latency, cache hit rate and other performance
# indicators. Uptime is calculated relative to a 30‑day window and alerts
# provide contextual information about recent system events. Where the
# underlying library `psutil` is unavailable the endpoint falls back to
# reasonable defaults.
@app.route('/api/system/monitoring', methods=['GET'])
def system_monitoring():
    try:
        # Calculate uptime percentage over a 30 day window. If the app has
        # been running for less than 30 days we extrapolate so the uptime
        # grows towards 100% as runtime approaches 30 days.
        now = datetime.utcnow()
        runtime = now - app_start_time
        thirty_days = timedelta(days=30)
        uptime_fraction = min(runtime.total_seconds() / thirty_days.total_seconds(), 1.0)
        uptime_percentage = round(uptime_fraction * 100, 2)

        # CPU and memory usage. Use psutil if available, else provide
        # placeholders. psutil.cpu_percent() without an interval returns
        # previously sampled results or 0.0 so we add a small interval.
        if psutil:
            cpu_usage = psutil.cpu_percent(interval=0.1)
            mem = psutil.virtual_memory()
            mem_usage = mem.percent
        else:
            cpu_usage = 20.0
            mem_usage = 40.0

        # Simulated network latency (ms) and bundle size (MB). These values
        # could be measured via application instrumentation. For now we set
        # conservative defaults.
        network_latency = 150  # milliseconds
        bundle_size = 2.4  # megabytes

        # Page performance metrics. These would typically come from the
        # front‑end (e.g. Web Vitals). Here we provide example values.
        perf_breakdown = {
            'firstContentfulPaint': 0.8,
            'largestContentfulPaint': 1.2,
            'firstInputDelay': 16,
            'cumulativeLayoutShift': 0.02
        }

        # Determine a simple performance grade based on CPU utilisation.
        if cpu_usage < 40 and mem_usage < 60:
            performance_grade = 'A'
        elif cpu_usage < 70 and mem_usage < 80:
            performance_grade = 'B'
        else:
            performance_grade = 'C'

        # Cache hit rate is a placeholder. In a real system this would be
        # derived from your caching layer. We compute a pseudo random value
        # based on uptime to simulate variation.
        cache_hit_rate = 70 + (uptime_fraction * 30)

        # Generate a simple performance timeline: 12 points representing
        # performance metrics sampled over the last period. We again use the
        # uptime to seed variation.
        timeline = []
        for i in range(12):
            # Each point oscillates between 20 and 100 depending on uptime and
            # index. This creates a chart that looks somewhat realistic.
            point = int(50 + 30 * (0.5 - ((now.minute + i) % 10) / 10) + uptime_fraction * 20)
            timeline.append(max(20, min(100, point)))

        # Prepare alerts. In a full implementation these would be generated
        # dynamically based on monitoring tools. Here we provide a couple of
        # static alerts with different severities.
        alerts = [
            {
                'level': 'warning',
                'title': 'High Database Load',
                'message': 'Database query execution time has increased by 25% in the last 10 minutes',
                'timestamp': now.isoformat()
            },
            {
                'level': 'info',
                'title': 'System Backup Completed',
                'message': 'Scheduled system backup completed successfully at 02:00 AM',
                'timestamp': (now - timedelta(minutes=10)).isoformat()
            },
            {
                'level': 'success',
                'title': 'Performance Optimization',
                'message': 'API response times improved by 15% after recent optimizations',
                'timestamp': (now - timedelta(minutes=20)).isoformat()
            }
        ]

        data = {
            'success': True,
            'systemOperational': True,
            'systemUptimePercent': uptime_percentage,
            'responseTimeMs': network_latency,
            'activeUsers': 1,  # Placeholder; in a real system track active sessions
            'errorRatePercent': 0.1,
            'alerts': alerts,
            'resourceUsage': {
                'cpuPercent': cpu_usage,
                'memoryPercent': mem_usage,
                'networkLatencyMs': network_latency,
                'bundleSizeMb': bundle_size
            },
            'performanceGrade': performance_grade,
            'pageLoadTimeSec': 1.2,
            'jsExecutionTimeSec': 0.8,
            'cacheHitRatePercent': round(cache_hit_rate, 1),
            'performanceBreakdown': perf_breakdown,
            'performanceRecommendations': [
                'Optimize image compression',
                'Enable lazy loading',
                'Implement service worker caching'
            ],
            'performanceTimeline': timeline
        }
        return jsonify(data), 200
    except Exception as e:
        # If anything goes wrong while computing the metrics, return a generic
        # error response.  We do not re‑raise because this endpoint is
        # informational and should never crash the application.
        return jsonify({'success': False, 'message': f'Error retrieving system monitoring data: {str(e)}'}), 500

# -----------------------------------------------------------------------------
# Payments & Settlements
#
# Vendors can record POS transactions via this endpoint. When a new payment
# record is created, the total amount is automatically split into shares
# for the manufacturer, NFEC, aggregator, IGR and the vendor. The split
# percentages are defined within the endpoint. Vendors can retrieve all
# previous payments for settlement history via a GET request.

@app.route('/api/vendor/payments', methods=['GET', 'POST'])
@token_required
def vendor_payments(current_user):
    if request.method == 'GET':
        try:
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)
            cursor.execute('''
                SELECT id, amount, purpose, payment_method,
                       manufacturer_share, nfec_share, aggregator_share,
                       igr_share, vendor_share, created_at
                FROM payments
                WHERE vendor_id = %s
                ORDER BY created_at DESC
            ''', (current_user['id'],))
            payments = cursor.fetchall()
            cursor.close()
            conn.close()
            return jsonify({
                'success': True,
                'payments': payments
            }), 200
        except Exception as e:
            return jsonify({
                'success': False,
                'message': f'Error fetching payments: {str(e)}'
            }), 500

    elif request.method == 'POST':
        try:
            data = request.get_json()
            required_fields = ['amount', 'purpose', 'paymentMethod']
            for field in required_fields:
                if field not in data or not data[field]:
                    return jsonify({
                        'success': False,
                        'message': f'{field} is required'
                    }), 400

            # Convert amount to decimal
            total_amount = float(data['amount'])
            if total_amount <= 0:
                return jsonify({
                    'success': False,
                    'message': 'Amount must be greater than zero'
                }), 400

            # Define static split percentages. Adjust these values to
            # reflect real‑world settlement agreements. They must add up to 1.0.
            splits = {
                'manufacturer': 0.30,
                'nfec': 0.30,
                'aggregator': 0.10,
                'igr': 0.10,
                'vendor': 0.20
            }
            manufacturer_share = round(total_amount * splits['manufacturer'], 2)
            nfec_share = round(total_amount * splits['nfec'], 2)
            aggregator_share = round(total_amount * splits['aggregator'], 2)
            igr_share = round(total_amount * splits['igr'], 2)
            vendor_share = round(total_amount * splits['vendor'], 2)

            payment_id = str(uuid.uuid4())
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO payments (
                    id, vendor_id, amount, purpose, payment_method,
                    manufacturer_share, nfec_share, aggregator_share,
                    igr_share, vendor_share
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ''', (
                payment_id,
                current_user['id'],
                total_amount,
                data['purpose'],
                data['paymentMethod'],
                manufacturer_share,
                nfec_share,
                aggregator_share,
                igr_share,
                vendor_share
            ))
            conn.commit()
            cursor.close()
            conn.close()
            return jsonify({
                'success': True,
                'message': 'Payment recorded successfully',
                'paymentId': payment_id
            }), 201
        except Exception as e:
            return jsonify({
                'success': False,
                'message': f'Error recording payment: {str(e)}'
            }), 500

# -----------------------------------------------------------------------------
# Training Materials
#
# Vendors can fetch available NFEC training materials via a GET request. The
# materials are seeded in the database during initialisation and can also be
# expanded by administrators. Vendors cannot create or modify materials.

@app.route('/api/vendor/training-materials', methods=['GET'])
@token_required
def vendor_training_materials(current_user):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute('''
            SELECT id, title, description, url, created_at
            FROM training_materials
            ORDER BY created_at DESC
        ''')
        materials = cursor.fetchall()
        cursor.close()
        conn.close()
        return jsonify({
            'success': True,
            'materials': materials
        }), 200
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error fetching training materials: {str(e)}'
        }), 500

# -----------------------------------------------------------------------------
# Certifications
#
# Vendors can submit staff for certification and view existing submissions.
# Each submission starts in a 'pending' state until NFEC administrators
# review and update it. Vendors cannot modify or delete certifications
# directly via this endpoint.

@app.route('/api/vendor/certifications', methods=['GET', 'POST'])
@token_required
def vendor_certifications(current_user):
    if request.method == 'GET':
        try:
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)
            cursor.execute('''
                SELECT id, staff_name, staff_email, staff_phone, status, created_at
                FROM certifications
                WHERE vendor_id = %s
                ORDER BY created_at DESC
            ''', (current_user['id'],))
            certifications = cursor.fetchall()
            cursor.close()
            conn.close()
            return jsonify({
                'success': True,
                'certifications': certifications
            }), 200
        except Exception as e:
            return jsonify({
                'success': False,
                'message': f'Error fetching certifications: {str(e)}'
            }), 500

    elif request.method == 'POST':
        try:
            data = request.get_json()
            required_fields = ['staffName']
            for field in required_fields:
                if field not in data or not data[field]:
                    return jsonify({
                        'success': False,
                        'message': f'{field} is required'
                    }), 400
            cert_id = str(uuid.uuid4())
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO certifications (
                    id, vendor_id, staff_name, staff_email, staff_phone
                ) VALUES (%s, %s, %s, %s, %s)
            ''', (
                cert_id,
                current_user['id'],
                data['staffName'],
                data.get('staffEmail', ''),
                data.get('staffPhone', '')
            ))
            conn.commit()
            cursor.close()
            conn.close()
            return jsonify({
                'success': True,
                'message': 'Certification submitted successfully',
                'certificationId': cert_id
            }), 201
        except Exception as e:
            return jsonify({
                'success': False,
                'message': f'Error submitting certification: {str(e)}'
            }), 500

# -----------------------------------------------------------------------------
# Compliance Audits
#
# Vendors can record compliance audits they have undertaken. Each audit
# includes a date, description, result and optional notes. Vendors can also
# retrieve previously recorded audits via a GET request.

@app.route('/api/vendor/compliance-audits', methods=['GET', 'POST'])
@token_required
def vendor_compliance_audits(current_user):
    if request.method == 'GET':
        try:
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)
            cursor.execute('''
                SELECT id, audit_date, description, result, notes, created_at
                FROM compliance_audits
                WHERE vendor_id = %s
                ORDER BY created_at DESC
            ''', (current_user['id'],))
            audits = cursor.fetchall()
            cursor.close()
            conn.close()
            return jsonify({
                'success': True,
                'audits': audits
            }), 200
        except Exception as e:
            return jsonify({
                'success': False,
                'message': f'Error fetching audits: {str(e)}'
            }), 500

    elif request.method == 'POST':
        try:
            data = request.get_json()
            required_fields = ['auditDate', 'result']
            for field in required_fields:
                if field not in data or not data[field]:
                    return jsonify({
                        'success': False,
                        'message': f'{field} is required'
                    }), 400
            audit_id = str(uuid.uuid4())
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO compliance_audits (
                    id, vendor_id, audit_date, description, result, notes
                ) VALUES (%s, %s, %s, %s, %s, %s)
            ''', (
                audit_id,
                current_user['id'],
                data['auditDate'],
                data.get('description', ''),
                data['result'],
                data.get('notes', '')
            ))
            conn.commit()
            cursor.close()
            conn.close()
            return jsonify({
                'success': True,
                'message': 'Compliance audit recorded successfully',
                'auditId': audit_id
            }), 201
        except Exception as e:
            return jsonify({
                'success': False,
                'message': f'Error recording audit: {str(e)}'
            }), 500

# -----------------------------------------------------------------------------
# Vendor Status & Notifications
#
# The vendor status endpoint calculates a simple honour/blacklist rating based
# on the vendor's activity. A higher number of sales improves the score
# while decommissions reduce it. If the score falls below a threshold the
# vendor is considered blacklisted. Notifications can be retrieved via
# the notifications endpoint.

@app.route('/api/vendor/status', methods=['GET'])
@token_required
def vendor_status(current_user):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        # Count sales and decommissions for rating calculation
        cursor.execute('SELECT COUNT(*) AS cnt FROM sales WHERE vendor_id = %s', (current_user['id'],))
        sales_count = cursor.fetchone()['cnt']
        cursor.execute('SELECT COUNT(*) AS cnt FROM decommissions WHERE vendor_id = %s', (current_user['id'],))
        decomm_count = cursor.fetchone()['cnt']
        # Simple scoring algorithm: each sale +2 points, each decommission -5 points
        rating = max(0, min(100, 100 + sales_count * 2 - decomm_count * 5))
        blacklisted = rating < 50
        cursor.close()
        conn.close()
        return jsonify({
            'success': True,
            'rating': rating,
            'blacklisted': blacklisted
        }), 200
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error fetching vendor status: {str(e)}'
        }), 500

@app.route('/api/vendor/notifications', methods=['GET'])
@token_required
def vendor_notifications(current_user):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute('''
            SELECT id, title, message, category, is_read, created_at
            FROM notifications
            WHERE vendor_id = %s
            ORDER BY created_at DESC
        ''', (current_user['id'],))
        notifications = cursor.fetchall()
        cursor.close()
        conn.close()
        return jsonify({
            'success': True,
            'notifications': notifications
        }), 200
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error fetching notifications: {str(e)}'
        }), 500

# -----------------------------------------------------------------------------
# Messaging & Reporting
#
# Vendors can send messages to the NFEC support/intelligence desk via the
# messages endpoint. Messages are appended to a simple chat log. Vendors
# can retrieve all past messages and submit new ones. Additionally, the
# reports endpoint allows vendors to submit structured incident reports.

@app.route('/api/vendor/messages', methods=['GET', 'POST'])
@token_required
def vendor_messages(current_user):
    if request.method == 'GET':
        try:
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)
            cursor.execute('''
                SELECT id, sender_type, content, created_at
                FROM messages
                WHERE vendor_id = %s
                ORDER BY created_at ASC
            ''', (current_user['id'],))
            messages = cursor.fetchall()
            cursor.close()
            conn.close()
            return jsonify({
                'success': True,
                'messages': messages
            }), 200
        except Exception as e:
            return jsonify({
                'success': False,
                'message': f'Error fetching messages: {str(e)}'
            }), 500

    elif request.method == 'POST':
        try:
            data = request.get_json()
            if not data or not data.get('content'):
                return jsonify({
                    'success': False,
                    'message': 'Message content is required'
                }), 400
            msg_id = str(uuid.uuid4())
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO messages (id, vendor_id, sender_type, content)
                VALUES (%s, %s, %s, %s)
            ''', (
                msg_id,
                current_user['id'],
                'vendor',
                data['content']
            ))
            conn.commit()
            cursor.close()
            conn.close()
            return jsonify({
                'success': True,
                'message': 'Message sent successfully',
                'messageId': msg_id
            }), 201
        except Exception as e:
            return jsonify({
                'success': False,
                'message': f'Error sending message: {str(e)}'
            }), 500

@app.route('/api/vendor/reports', methods=['POST'])
@token_required
def vendor_reports(current_user):
    try:
        data = request.get_json()
        required_fields = ['subject', 'description', 'category']
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({
                    'success': False,
                    'message': f'{field} is required'
                }), 400
        report_id = str(uuid.uuid4())
        conn = get_db_connection()
        cursor = conn.cursor()
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
        cursor.close()
        conn.close()
        return jsonify({
            'success': True,
            'message': 'Report submitted successfully',
            'reportId': report_id
        }), 201
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error submitting report: {str(e)}'
        }), 500

# -----------------------------------------------------------------------------
# Route to serve decommission evidence images
#
# Uploaded evidence images are stored in the configured UPLOAD_FOLDER. This
# endpoint uses Flask's `send_from_directory` to expose those files to the
# client. The filename parameter must exactly match a file stored in the
# directory; attempts to traverse directories are prevented.
@app.route('/uploads/decommissions/<filename>')
def serve_decommission_evidence(filename):
    """
    Serve a decommission evidence image from the uploads folder.

    Args:
        filename: The name of the evidence file to serve. This should
            correspond to a file previously saved in the UPLOAD_FOLDER.

    Returns:
        A Flask response that streams the requested file with appropriate
        headers. If the file does not exist, Flask will return a 404.
    """
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


# -----------------------------------------------------------------------------
# Administration Endpoints
#
# The following routes provide functionality for NFEC/FFS administrators. They
# allow an administrator to log in, view and manage vendors, manage QR
# codes, access aggregated analytics, inspect payment records, certification
# submissions and reports. Each route is protected by the @admin_token_required
# decorator defined at the top of this file. See the AdminDashboard React
# component for examples of how these endpoints are consumed.

@app.route('/api/admin/login', methods=['POST'])
def admin_login():
    """
    Authenticate an administrator and issue a JWT token.

    Expects a JSON payload with `username` and `password`. On success
    returns a token that must be provided in the Authorization header for
    subsequent admin requests. On failure returns an error message.
    """
    try:
        data = request.get_json()
        if not data or not data.get('username') or not data.get('password'):
            return jsonify({'success': False, 'message': 'Username and password are required'}), 400
        username = data.get('username')
        password = data.get('password')
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            token = jwt.encode({'username': username, 'role': 'admin'}, app.config['SECRET_KEY'], algorithm='HS256')
            return jsonify({'success': True, 'message': 'Login successful', 'token': token}), 200
        else:
            return jsonify({'success': False, 'message': 'Invalid administrator credentials'}), 401
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500


@app.route('/api/admin/vendors', methods=['GET'])
@admin_token_required
def admin_get_vendors(current_admin):
    """
    Retrieve a list of all registered vendors regardless of status.

    Returns a JSON list of vendor records with key fields including id,
    contact_name, email, phone, business_address, state, local_government,
    category and status.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute('''
            SELECT id, contact_name, email, phone, business_address, state,
                   local_government, category, status, created_at
            FROM vendors
            ORDER BY created_at DESC
        ''')
        vendors = cursor.fetchall()
        cursor.close()
        conn.close()
        return jsonify({'success': True, 'vendors': vendors}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500


@app.route('/api/admin/vendors/<vendor_id>', methods=['PUT'])
@admin_token_required
def admin_update_vendor(current_admin, vendor_id):
    """
    Update the status of a vendor. The request body must include a
    `status` field with one of the allowed values: 'approved', 'rejected'
    or 'pending'. On success returns a confirmation message.
    """
    try:
        data = request.get_json()
        if not data or 'status' not in data:
            return jsonify({'success': False, 'message': 'Status field is required'}), 400
        status = data['status']
        if status not in ['approved', 'rejected', 'pending']:
            return jsonify({'success': False, 'message': 'Invalid status. Must be approved, rejected or pending'}), 400
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('UPDATE vendors SET status = %s WHERE id = %s', (status, vendor_id))
        if cursor.rowcount == 0:
            conn.rollback()
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'message': 'Vendor not found'}), 404
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({'success': True, 'message': f'Vendor status updated to {status}'}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500


@app.route('/api/admin/qrcodes', methods=['GET'])
@admin_token_required
def admin_get_qrcodes(current_admin):
    """
    Retrieve all QR codes in the system along with the vendor contact name.

    Returns a JSON list with each QR code's id, vendor_id, product_type,
    size, type, status, created_at, activated_at and the associated vendor
    contact_name.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute('''
            SELECT q.id, q.vendor_id, v.contact_name, q.product_type, q.size,
                   q.type AS qr_type, q.status, q.created_at, q.activated_at
            FROM qr_codes q
            JOIN vendors v ON q.vendor_id = v.id
            ORDER BY q.created_at DESC
        ''')
        qrcodes = cursor.fetchall()
        cursor.close()
        conn.close()
        return jsonify({'success': True, 'qrcodes': qrcodes}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500


@app.route('/api/admin/qrcodes/<qr_id>', methods=['PUT'])
@admin_token_required
def admin_update_qrcode(current_admin, qr_id):
    """
    Update the status of a QR code. The request body must include a
    `status` field with one of the allowed values: 'active', 'inactive'
    or 'pending'. The endpoint updates the qr_codes table accordingly.
    """
    try:
        data = request.get_json()
        if not data or 'status' not in data:
            return jsonify({'success': False, 'message': 'Status field is required'}), 400
        status = data['status']
        if status not in ['active', 'inactive', 'pending']:
            return jsonify({'success': False, 'message': 'Invalid status. Must be active, inactive or pending'}), 400
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('UPDATE qr_codes SET status = %s WHERE id = %s', (status, qr_id))
        if cursor.rowcount == 0:
            conn.rollback()
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'message': 'QR code not found'}), 404
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({'success': True, 'message': f'QR code status updated to {status}'}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500


@app.route('/api/admin/analytics', methods=['GET'])
@admin_token_required
def admin_get_analytics(current_admin):
    """
    Return aggregated analytics across vendors and QR codes.

    The response includes counts of vendors by status, QR codes by status,
    vendors by state, and QR codes by product type. Additional metrics
    can be added as needed.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        # Vendor counts by status
        cursor.execute('SELECT status, COUNT(*) AS count FROM vendors GROUP BY status')
        vendor_status_rows = cursor.fetchall()
        vendorStatus = {row['status']: row['count'] for row in vendor_status_rows}
        # Vendors by state
        cursor.execute('SELECT state, COUNT(*) AS count FROM vendors GROUP BY state')
        vendors_by_state = cursor.fetchall()
        # QR code counts by status
        cursor.execute('SELECT status, COUNT(*) AS count FROM qr_codes GROUP BY status')
        qr_status_rows = cursor.fetchall()
        qrStatus = {row['status']: row['count'] for row in qr_status_rows}
        # QR codes by product type
        cursor.execute('SELECT product_type, COUNT(*) AS count FROM qr_codes GROUP BY product_type')
        qr_by_type_rows = cursor.fetchall()
        qrByType = {row['product_type']: row['count'] for row in qr_by_type_rows}
        cursor.close()
        conn.close()
        analytics = {
            'vendorStatus': vendorStatus,
            'vendorsByState': vendors_by_state,
            'qrStatus': qrStatus,
            'qrByType': qrByType
        }
        return jsonify({'success': True, 'analytics': analytics}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500


@app.route('/api/admin/payments', methods=['GET'])
@admin_token_required
def admin_get_payments(current_admin):
    """
    Retrieve all payment records across all vendors. Useful for
    settlement reconciliation and auditing. Each record includes the
    vendor_id, vendor contact name, amount, purpose, payment method and the
    computed shares for the manufacturer, NFEC, aggregator, IGR and vendor.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute('''
            SELECT p.id, p.vendor_id, v.contact_name, p.amount, p.purpose,
                   p.payment_method, p.manufacturer_share, p.nfec_share,
                   p.aggregator_share, p.igr_share, p.vendor_share, p.created_at
            FROM payments p
            JOIN vendors v ON p.vendor_id = v.id
            ORDER BY p.created_at DESC
        ''')
        payments = cursor.fetchall()
        cursor.close()
        conn.close()
        return jsonify({'success': True, 'payments': payments}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500


@app.route('/api/admin/certifications', methods=['GET'])
@admin_token_required
def admin_get_certifications(current_admin):
    """
    Retrieve all staff certification records submitted by vendors. The
    response includes vendor contact name and certification details. This
    endpoint can be extended to support approving or rejecting
    certifications.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute('''
            SELECT c.id, c.vendor_id, v.contact_name, c.staff_name, c.staff_email,
                   c.staff_phone, c.status, c.created_at
            FROM certifications c
            JOIN vendors v ON c.vendor_id = v.id
            ORDER BY c.created_at DESC
        ''')
        certifications = cursor.fetchall()
        cursor.close()
        conn.close()
        return jsonify({'success': True, 'certifications': certifications}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500


@app.route('/api/admin/reports', methods=['GET'])
@admin_token_required
def admin_get_reports(current_admin):
    """
    Retrieve all vendor submitted reports. Each report contains a subject,
    description, category and the vendor contact name. Administrators use
    this information to investigate incidents and suspicious behaviour.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute('''
            SELECT r.id, r.vendor_id, v.contact_name, r.subject, r.description,
                   r.category, r.created_at
            FROM reports r
            JOIN vendors v ON r.vendor_id = v.id
            ORDER BY r.created_at DESC
        ''')
        reports = cursor.fetchall()
        cursor.close()
        conn.close()
        return jsonify({'success': True, 'reports': reports}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500

# -----------------------------------------------------------------------------
# Admin messages endpoint
#
# This route allows an administrator to view and send chat messages to a
# specific vendor.  Administrators can retrieve the full message history with a
# vendor (GET) and send a new message (POST).  Messages are stored in the
# ``messages`` table with sender_type set to 'admin' when sent by an
# administrator.  Vendors retrieve these messages via the existing
# /api/vendor/messages endpoint.  Only authenticated admins can call this
# endpoint.

@app.route('/api/admin/messages/<vendor_id>', methods=['GET', 'POST'])
@admin_token_required
def admin_messages(current_admin, vendor_id):
    try:
        if request.method == 'GET':
            # Retrieve all messages exchanged with the vendor
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)
            cursor.execute('''
                SELECT id, sender_type, content, created_at
                FROM messages
                WHERE vendor_id = %s
                ORDER BY created_at ASC
            ''', (vendor_id,))
            msgs = cursor.fetchall()
            cursor.close(); conn.close()
            return jsonify({'success': True, 'messages': msgs}), 200
        else:
            # Send a message to the vendor
            data = request.get_json() or {}
            content = data.get('content')
            if not content:
                return jsonify({'success': False, 'message': 'Message content is required'}), 400
            msg_id = str(uuid.uuid4())
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO messages (id, vendor_id, sender_type, content)
                VALUES (%s, %s, %s, %s)
            ''', (msg_id, vendor_id, 'admin', content))
            conn.commit()
            cursor.close(); conn.close()
            return jsonify({'success': True, 'message': 'Message sent successfully', 'messageId': msg_id}), 201
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error processing messages: {str(e)}'}), 500


# -----------------------------------------------------------------------------
# Mobile Application Endpoints
#
# These routes support the public‑facing FEIMS mobile web app. They allow
# citizens and field officers to verify QR codes, submit extinguisher data,
# book training sessions, make payments and locate NFEC approved vendors.

@app.route('/api/mobile/capture', methods=['POST'])
def mobile_capture():
    """
    Capture fire extinguisher or DCP details via the mobile app.

    Expects a JSON payload with at least a `productType` field set to
    'existing_extinguisher', 'new_extinguisher' or 'dcp_sachet' and a
    `data` object containing the fields relevant to the chosen type. The
    data object is stored as JSON for later administrative review. Returns
    the ID of the created entry.
    """
    try:
        data = request.get_json()
        if not data or 'productType' not in data or 'data' not in data:
            return jsonify({'success': False, 'message': 'productType and data are required'}), 400
        product_type = data['productType']
        details = data['data']
        if product_type not in ['existing_extinguisher', 'new_extinguisher', 'dcp_sachet']:
            return jsonify({'success': False, 'message': 'Invalid productType'}), 400
        entry_id = str(uuid.uuid4())
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO mobile_entries (id, product_type, data)
            VALUES (%s, %s, %s)
        ''', (entry_id, product_type, json.dumps(details)))
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({'success': True, 'message': 'Data captured successfully', 'entryId': entry_id}), 201
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error capturing data: {str(e)}'}), 500


@app.route('/api/mobile/book-training', methods=['POST'])
def mobile_book_training():
    """
    Book a training session via the mobile app.

    Requires JSON with `name`, `phone`, `plateOrAddress`, `bookingDate` and
    `bookingTime`. Stores the booking for later approval and returns a
    booking ID.
    """
    try:
        data = request.get_json()
        required = ['name', 'phone', 'plateOrAddress', 'bookingDate', 'bookingTime']
        for field in required:
            if not data or field not in data or not data[field]:
                return jsonify({'success': False, 'message': f'{field} is required'}), 400
        booking_id = str(uuid.uuid4())
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO training_bookings (id, name, phone, plate_or_address, booking_date, booking_time)
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
        cursor.close()
        conn.close()
        return jsonify({'success': True, 'message': 'Training booked successfully', 'bookingId': booking_id}), 201
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error booking training: {str(e)}'}), 500


@app.route('/api/mobile/pay', methods=['POST'])
def mobile_pay():
    """
    Record a payment made via the mobile app.

    Expects JSON with `amount`, `purpose` and `paymentMethod`. The payment
    is split into NFEC, aggregator and IGR shares (40%, 30%, 30%) and stored
    in the mobile_payments table. Returns the payment ID and computed
    breakdown.
    """
    try:
        data = request.get_json()
        required = ['amount', 'purpose', 'paymentMethod']
        for field in required:
            if not data or field not in data or not data[field]:
                return jsonify({'success': False, 'message': f'{field} is required'}), 400
        amount = float(data['amount'])
        purpose = data['purpose']
        payment_method = data['paymentMethod']
        if payment_method not in ['cash', 'transfer', 'card', 'pos']:
            return jsonify({'success': False, 'message': 'Invalid paymentMethod'}), 400
        # Compute shares: 40% NFEC, 30% aggregator, 30% IGR
        nfec_share = round(amount * 0.4, 2)
        aggregator_share = round(amount * 0.3, 2)
        igr_share = round(amount * 0.3, 2)
        payment_id = str(uuid.uuid4())
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO mobile_payments (id, amount, purpose, payment_method, nfec_share, aggregator_share, igr_share)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        ''', (
            payment_id,
            amount,
            purpose,
            payment_method,
            nfec_share,
            aggregator_share,
            igr_share
        ))
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({
            'success': True,
            'message': 'Payment recorded successfully',
            'paymentId': payment_id,
            'breakdown': {
                'nfecShare': nfec_share,
                'aggregatorShare': aggregator_share,
                'igrShare': igr_share
            }
        }), 201
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error recording payment: {str(e)}'}), 500


@app.route('/api/mobile/vendor-locator', methods=['GET'])
def mobile_vendor_locator():
    """
    Locate NFEC approved vendors by state and optionally local government area.

    Query parameters:
      - state: required, vendor state to search within
      - lga: optional, local government area for finer filtering

    Returns a list of vendors with their contact name, phone, business address,
    state, local government and category.
    """
    try:
        state = request.args.get('state')
        lga = request.args.get('lga')
        if not state:
            return jsonify({'success': False, 'message': 'state is required'}), 400
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        if lga:
            cursor.execute('''
                SELECT contact_name, phone, business_address, state, local_government, category
                FROM vendors
                WHERE state = %s AND local_government = %s AND status = 'approved'
            ''', (state, lga))
        else:
            cursor.execute('''
                SELECT contact_name, phone, business_address, state, local_government, category
                FROM vendors
                WHERE state = %s AND status = 'approved'
            ''', (state,))
        vendors_list = cursor.fetchall()
        cursor.close()
        conn.close()
        return jsonify({'success': True, 'vendors': vendors_list}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error locating vendors: {str(e)}'}), 500


# -----------------------------------------------------------------------------
# Fire Extinguisher Data Capture & Analytics
#
# FEIMS distinguishes between QR code management and fire extinguisher data
# management.  Whereas QR codes are tied to individual extinguishers/DCP units
# at the time of manufacture or servicing, the data management module allows
# vendors and the general public to submit details about extinguishers,
# independent of the QR lifecycle.  These details may come from vehicles,
# buildings or decommissioning events, and are stored in either the
# ``mobile_entries`` or ``vendor_entries`` tables.  The following routes
# provide an API for vendors to capture extinguisher data and for
# administrators to retrieve and analyse all captured entries.

@app.route('/api/vendor/capture-extinguisher', methods=['POST'])
@token_required
def vendor_capture_extinguisher(current_user):
    """
    Capture fire extinguisher or DCP details via the vendor dashboard.

    Accepts a JSON payload with:
      - productType: one of 'existing_extinguisher', 'new_extinguisher' or 'dcp_sachet'
      - data: an object containing the submitted fields (e.g. plateNumber,
        buildingAddress, manufacturingDate, expiryDate, etc.).

    The entry is stored in the vendor_entries table along with the vendor ID.
    This endpoint mirrors the public-facing mobile_capture route but associates
    the entry with a vendor. Returns the ID of the created entry.
    """
    try:
        payload = request.get_json()
        if not payload or 'productType' not in payload or 'data' not in payload:
            return jsonify({'success': False, 'message': 'productType and data are required'}), 400
        product_type = payload['productType']
        details = payload['data']
        if product_type not in ['existing_extinguisher', 'new_extinguisher', 'dcp_sachet']:
            return jsonify({'success': False, 'message': 'Invalid productType'}), 400
        entry_id = str(uuid.uuid4())
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO vendor_entries (id, vendor_id, product_type, data)
            VALUES (%s, %s, %s, %s)
        ''', (entry_id, current_user['id'], product_type, json.dumps(details)))
        conn.commit()
        cursor.close(); conn.close()
        return jsonify({'success': True, 'message': 'Data captured successfully', 'entryId': entry_id}), 201
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error capturing data: {str(e)}'}), 500


@app.route('/api/admin/extinguisher-entries', methods=['GET'])
@admin_token_required
def admin_get_extinguisher_entries(current_admin):
    """
    Retrieve all fire extinguisher/DCP entries submitted via both mobile and vendor channels.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Fetch mobile entries
        cursor.execute('''
            SELECT id, product_type, data, created_at
            FROM mobile_entries
            ORDER BY created_at DESC
        ''')
        mobile_entries = cursor.fetchall()
        
        # Fetch vendor entries
        cursor.execute('''
            SELECT id, vendor_id, product_type, data, created_at
            FROM vendor_entries
            ORDER BY created_at DESC
        ''')
        vendor_entries = cursor.fetchall()
        
        entries = []
        
        # Helper function to safely parse data
        def parse_data(data):
            if data is None:
                return {}
            try:
                # Handle binary data
                if isinstance(data, bytes):
                    data = data.decode('utf-8')
                # Parse JSON string
                if isinstance(data, str):
                    return json.loads(data)
                # Already a dict or other type
                return data
            except (json.JSONDecodeError, UnicodeDecodeError):
                # Return empty dict if parsing fails
                return {}
        
        # Format mobile entries
        for row in mobile_entries:
            entries.append({
                'id': row['id'],
                'source': 'mobile',
                'vendorId': None,
                'productType': row['product_type'],
                'data': parse_data(row['data']),
                'createdAt': row['created_at'].isoformat() if row['created_at'] else None
            })
        
        # Format vendor entries
        for row in vendor_entries:
            entries.append({
                'id': row['id'],
                'source': 'vendor',
                'vendorId': row['vendor_id'],
                'productType': row['product_type'],
                'data': parse_data(row['data']),
                'createdAt': row['created_at'].isoformat() if row['created_at'] else None
            })
        
        # Combine and sort by createdAt descending
        entries.sort(key=lambda x: x['createdAt'] or '', reverse=True)
        
        cursor.close()
        conn.close()
        
        return jsonify({'success': True, 'entries': entries}), 200
        
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error retrieving entries: {str(e)}'}), 500

@app.route('/api/admin/training/stats', methods=['GET'])
@admin_token_required
def admin_training_stats(current_admin):
    """
    Retrieve training statistics for the admin dashboard.
    
    Returns counts of training bookings by status, monthly trends,
    and other training-related metrics.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Get total training bookings count
        cursor.execute('SELECT COUNT(*) as total FROM training_bookings')
        total_result = cursor.fetchone()
        total_bookings = total_result['total'] if total_result else 0
        
        # Get bookings by month (last 6 months)
        cursor.execute('''
            SELECT 
                DATE_FORMAT(created_at, '%Y-%m') as month,
                COUNT(*) as count
            FROM training_bookings 
            WHERE created_at >= DATE_SUB(NOW(), INTERVAL 6 MONTH)
            GROUP BY DATE_FORMAT(created_at, '%Y-%m')
            ORDER BY month
        ''')
        monthly_trends = cursor.fetchall()
        
        cursor.close()
        conn.close()
        
        stats = {
            'total': total_bookings,
            'monthly': monthly_trends
        }
        
        return jsonify({'success': True, 'stats': stats}), 200
        
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error fetching training stats: {str(e)}'}), 500
    
    
@app.route('/api/admin/extinguisher-summary', methods=['GET'])
@admin_token_required
def admin_extinguisher_summary(current_admin):
    """
    Provide aggregated statistics about captured fire extinguisher and DCP data.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Fetch all entries from both tables
        cursor.execute('SELECT product_type, data, created_at FROM mobile_entries')
        mobile_rows = cursor.fetchall()
        
        cursor.execute('SELECT product_type, data, created_at FROM vendor_entries')
        vendor_rows = cursor.fetchall()
        
        cursor.close()
        conn.close()

        # Helper function to safely parse data (same as above)
        def parse_data(data):
            if data is None:
                return {}
            try:
                if isinstance(data, bytes):
                    data = data.decode('utf-8')
                if isinstance(data, str):
                    return json.loads(data)
                return data
            except (json.JSONDecodeError, UnicodeDecodeError):
                return {}

        # ... rest of the function remains the same, but use parse_data() helper
        total_entries = 0
        by_source = {'mobile': 0, 'vendor': 0}
        by_product_type = {'existing_extinguisher': 0, 'new_extinguisher': 0, 'dcp_sachet': 0}
        classification_counts = {'vehicle': 0, 'building': 0, 'decommissioned': 0, 'adhoc': 0}
        by_state = {}
        by_local_government = {}
        expired_count = 0

        # Helper to process each entry (updated to use parse_data)
        def process_entry(row, source):
            nonlocal total_entries, by_source, by_product_type, classification_counts, by_state, by_local_government, expired_count
            total_entries += 1
            by_source[source] += 1
            product_type = row['product_type']
            by_product_type[product_type] = by_product_type.get(product_type, 0) + 1
            
            # Parse data safely
            data = parse_data(row['data'])
            
            # ... rest of the processing logic remains the same
            classification = 'adhoc'
            lowered = {k.lower(): v for k, v in data.items()} if isinstance(data, dict) else {}
            
            if lowered.get('plate_number') or lowered.get('platenumber') or lowered.get('plate'):
                classification = 'vehicle'
            elif lowered.get('building_address') or lowered.get('buildingaddress'):
                classification = 'building'
            
            # Check expiry date
            expiry_value = lowered.get('expiry_date') or lowered.get('expirydate') or lowered.get('expiry')
            is_expired = False
            if expiry_value:
                try:
                    expiry_dt = datetime.fromisoformat(expiry_value)
                    if expiry_dt.date() < datetime.utcnow().date():
                        is_expired = True
                except Exception:
                    pass
            if is_expired:
                classification_counts['decommissioned'] += 1
                expired_count += 1
            
            classification_counts[classification] = classification_counts.get(classification, 0) + 1
            
            # State/local government counts
            state = lowered.get('state')
            lga = lowered.get('local_government') or lowered.get('localgovernment') or lowered.get('lga')
            if state:
                by_state[state] = by_state.get(state, 0) + 1
                if lga:
                    key = (state, lga)
                    by_local_government[key] = by_local_government.get(key, 0) + 1

        for row in mobile_rows:
            process_entry(row, 'mobile')
        for row in vendor_rows:
            process_entry(row, 'vendor')

        summary = {
            'totalEntries': total_entries,
            'bySource': by_source,
            'byProductType': by_product_type,
            'classificationCounts': classification_counts,
            'byState': by_state,
            'byLocalGovernment': {f'{state}/{lga}': count for (state, lga), count in by_local_government.items()},
            'expiredCount': expired_count
        }
        
        return jsonify({'success': True, 'summary': summary}), 200
        
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error computing summary: {str(e)}'}), 500

if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5001)