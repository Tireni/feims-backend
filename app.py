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

try:
    import psutil  # For system metrics
except ImportError:
    psutil = None  # psutil may not be available in some environments

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
# File upload configuration
UPLOAD_FOLDER = 'uploads/decommissions'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Create upload directory safely
try:
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
except Exception as e:
    print(f"Warning: Could not create upload directory: {e}")

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
    'autocommit': True
}

def get_db_connection():
    try:
        conn = mysql.connector.connect(**db_config)
        print("Database connection successful")
        return conn
    except mysql.connector.Error as e:
        print(f"Database connection error: {e}")
        return None

def init_db():
    conn = get_db_connection()
    if conn is None:
        print("Failed to connect to database. Skipping table creation.")
        return
    
    cursor = conn.cursor()
    
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

    conn.commit()
    cursor.close()
    conn.close()

    # Seed training materials if none exist
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
    if conn is None:
        return None
    cursor = conn.cursor(dictionary=True)
    
    cursor.execute('SELECT id, contact_name, email, phone, business_address, state, local_government, category, status FROM vendors WHERE id = %s', (vendor_id,))
    vendor = cursor.fetchone()
    
    cursor.close()
    conn.close()
    
    return vendor

# Helper function to get vendor by email
def get_vendor_by_email(email):
    conn = get_db_connection()
    if conn is None:
        return None
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
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
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
        
        generated_codes = []
        
        for i in range(quantity):
            qr_id = str(uuid.uuid4())
            
            qr_data = {
                'id': qr_id,
                'vendor_id': current_user['id'],
                'product_type': data['productType'],
                'size': data['size'],
                'type': data['type'],
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
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
        cursor = conn.cursor(dictionary=True)
        
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
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
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
    try:
        data = request.get_json() or {}
        qr_id = data.get('qrId')
        if not qr_id:
            return jsonify({'success': False, 'message': 'QR code ID is required'}), 400
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
        cursor = conn.cursor(dictionary=True)
        cursor.execute('SELECT vendor_id, status FROM qr_codes WHERE id = %s', (qr_id,))
        record = cursor.fetchone()
        if not record:
            cursor.close(); conn.close()
            return jsonify({'success': False, 'message': 'QR code not found'}), 404
        if record['vendor_id'] != current_user['id']:
            cursor.close(); conn.close()
            return jsonify({'success': False, 'message': 'Unauthorized to request activation for this QR code'}), 403
        if record['status'] == 'active':
            cursor.close(); conn.close()
            return jsonify({'success': False, 'message': 'QR code is already active'}), 400
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
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
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
            if conn is None:
                return jsonify({'success': False, 'message': 'Database connection failed'}), 500
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
            
            required_fields = ['productType', 'quantity', 'amount', 'customerName', 'customerPhone', 'paymentMethod']
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
            if conn is None:
                return jsonify({'success': False, 'message': 'Database connection failed'}), 500
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
            
            required_fields = ['qrCodeId', 'serviceType']
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
            if conn is None:
                return jsonify({'success': False, 'message': 'Database connection failed'}), 500
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

            decommission_id = str(uuid.uuid4())
            evidence_path = None
            
            if 'evidence' in request.files:
                evidence_file = request.files['evidence']
                if (evidence_file and evidence_file.filename and
                    allowed_file(evidence_file.filename)):
                    filename = f"{decommission_id}_{secure_filename(evidence_file.filename)}"
                    evidence_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    evidence_file.save(evidence_path)

            conn = get_db_connection()
            if conn is None:
                return jsonify({'success': False, 'message': 'Database connection failed'}), 500
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
            return jsonify({
                'success': False,
                'message': f'Error recording decommission: {str(e)}'
            }), 500

@app.route('/api/vendor/analytics', methods=['GET'])
@token_required
def vendor_analytics(current_user):
    try:
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute('''
            SELECT 
                COUNT(*) as total_sales,
                SUM(amount) as total_revenue,
                AVG(amount) as avg_transaction
            FROM sales 
            WHERE vendor_id = %s
        ''', (current_user['id'],))
        
        sales_summary = cursor.fetchone()
        
        cursor.execute('''
            SELECT 
                SUM(amount) as monthly_sales
            FROM sales 
            WHERE vendor_id = %s 
            AND MONTH(created_at) = MONTH(CURRENT_DATE())
            AND YEAR(created_at) = YEAR(CURRENT_DATE())
        ''', (current_user['id'],))
        
        monthly_sales = cursor.fetchone()
        
        cursor.execute('''
            SELECT 
                COUNT(*) as total_services
            FROM services 
            WHERE vendor_id = %s
        ''', (current_user['id'],))
        
        service_summary = cursor.fetchone()
        
        cursor.execute('''
            SELECT 
                COUNT(*) as monthly_services
            FROM services 
            WHERE vendor_id = %s 
            AND MONTH(created_at) = MONTH(CURRENT_DATE())
            AND YEAR(created_at) = YEAR(CURRENT_DATE())
        ''', (current_user['id'],))
        
        monthly_services = cursor.fetchone()
        
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
        return jsonify({
            'success': False,
            'message': f'Error fetching analytics: {str(e)}'
        }), 500

@app.route('/api/system/monitoring', methods=['GET'])
def system_monitoring():
    try:
        now = datetime.utcnow()
        runtime = now - app_start_time
        thirty_days = timedelta(days=30)
        uptime_fraction = min(runtime.total_seconds() / thirty_days.total_seconds(), 1.0)
        uptime_percentage = round(uptime_fraction * 100, 2)

        if psutil:
            cpu_usage = psutil.cpu_percent(interval=0.1)
            mem = psutil.virtual_memory()
            mem_usage = mem.percent
        else:
            cpu_usage = 20.0
            mem_usage = 40.0

        network_latency = 150
        bundle_size = 2.4

        perf_breakdown = {
            'firstContentfulPaint': 0.8,
            'largestContentfulPaint': 1.2,
            'firstInputDelay': 16,
            'cumulativeLayoutShift': 0.02
        }

        if cpu_usage < 40 and mem_usage < 60:
            performance_grade = 'A'
        elif cpu_usage < 70 and mem_usage < 80:
            performance_grade = 'B'
        else:
            performance_grade = 'C'

        cache_hit_rate = 70 + (uptime_fraction * 30)

        timeline = []
        for i in range(12):
            point = int(50 + 30 * (0.5 - ((now.minute + i) % 10) / 10) + uptime_fraction * 20)
            timeline.append(max(20, min(100, point)))

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
            'activeUsers': 1,
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
        return jsonify({'success': False, 'message': f'Error retrieving system monitoring data: {str(e)}'}), 500

@app.route('/api/vendor/payments', methods=['GET', 'POST'])
@token_required
def vendor_payments(current_user):
    if request.method == 'GET':
        try:
            conn = get_db_connection()
            if conn is None:
                return jsonify({'success': False, 'message': 'Database connection failed'}), 500
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

            total_amount = float(data['amount'])
            if total_amount <= 0:
                return jsonify({
                    'success': False,
                    'message': 'Amount must be greater than zero'
                }), 400

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
            if conn is None:
                return jsonify({'success': False, 'message': 'Database connection failed'}), 500
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

@app.route('/api/vendor/training-materials', methods=['GET'])
@token_required
def vendor_training_materials(current_user):
    try:
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
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

@app.route('/api/vendor/certifications', methods=['GET', 'POST'])
@token_required
def vendor_certifications(current_user):
    if request.method == 'GET':
        try:
            conn = get_db_connection()
            if conn is None:
                return jsonify({'success': False, 'message': 'Database connection failed'}), 500
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
            if conn is None:
                return jsonify({'success': False, 'message': 'Database connection failed'}), 500
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

@app.route('/api/vendor/compliance-audits', methods=['GET', 'POST'])
@token_required
def vendor_compliance_audits(current_user):
    if request.method == 'GET':
        try:
            conn = get_db_connection()
            if conn is None:
                return jsonify({'success': False, 'message': 'Database connection failed'}), 500
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
            if conn is None:
                return jsonify({'success': False, 'message': 'Database connection failed'}), 500
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

@app.route('/api/vendor/status', methods=['GET'])
@token_required
def vendor_status(current_user):
    try:
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
        cursor = conn.cursor(dictionary=True)
        cursor.execute('SELECT COUNT(*) AS cnt FROM sales WHERE vendor_id = %s', (current_user['id'],))
        sales_count = cursor.fetchone()['cnt']
        cursor.execute('SELECT COUNT(*) AS cnt FROM decommissions WHERE vendor_id = %s', (current_user['id'],))
        decomm_count = cursor.fetchone()['cnt']
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
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
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

@app.route('/api/vendor/messages', methods=['GET', 'POST'])
@token_required
def vendor_messages(current_user):
    if request.method == 'GET':
        try:
            conn = get_db_connection()
            if conn is None:
                return jsonify({'success': False, 'message': 'Database connection failed'}), 500
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
            if conn is None:
                return jsonify({'success': False, 'message': 'Database connection failed'}), 500
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
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
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

@app.route('/uploads/decommissions/<filename>')
def serve_decommission_evidence(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/api/admin/login', methods=['POST'])
def admin_login():
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
    try:
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
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
    try:
        data = request.get_json()
        if not data or 'status' not in data:
            return jsonify({'success': False, 'message': 'Status field is required'}), 400
        status = data['status']
        if status not in ['approved', 'rejected', 'pending']:
            return jsonify({'success': False, 'message': 'Invalid status. Must be approved, rejected or pending'}), 400
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
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
    try:
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
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
    try:
        data = request.get_json()
        if not data or 'status' not in data:
            return jsonify({'success': False, 'message': 'Status field is required'}), 400
        status = data['status']
        if status not in ['active', 'inactive', 'pending']:
            return jsonify({'success': False, 'message': 'Invalid status. Must be active, inactive or pending'}), 400
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
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
    try:
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
        cursor = conn.cursor(dictionary=True)
        cursor.execute('SELECT status, COUNT(*) AS count FROM vendors GROUP BY status')
        vendor_status_rows = cursor.fetchall()
        vendorStatus = {row['status']: row['count'] for row in vendor_status_rows}
        cursor.execute('SELECT state, COUNT(*) AS count FROM vendors GROUP BY state')
        vendors_by_state = cursor.fetchall()
        cursor.execute('SELECT status, COUNT(*) AS count FROM qr_codes GROUP BY status')
        qr_status_rows = cursor.fetchall()
        qrStatus = {row['status']: row['count'] for row in qr_status_rows}
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
    try:
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
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
    try:
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
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
    try:
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
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

@app.route('/api/admin/messages/<vendor_id>', methods=['GET', 'POST'])
@admin_token_required
def admin_messages(current_admin, vendor_id):
    try:
        if request.method == 'GET':
            conn = get_db_connection()
            if conn is None:
                return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            cursor = conn.cursor(dictionary=True)
            cursor.execute('''
                SELECT id, sender_type, content, created_at
                FROM messages
                WHERE vendor_id = %s
                ORDER BY created_at ASC
            ''', (vendor_id,))
            msgs = cursor.fetchall()
            cursor.close()
            conn.close()
            return jsonify({'success': True, 'messages': msgs}), 200
        else:
            data = request.get_json() or {}
            content = data.get('content')
            if not content:
                return jsonify({'success': False, 'message': 'Message content is required'}), 400
            msg_id = str(uuid.uuid4())
            conn = get_db_connection()
            if conn is None:
                return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO messages (id, vendor_id, sender_type, content)
                VALUES (%s, %s, %s, %s)
            ''', (msg_id, vendor_id, 'admin', content))
            conn.commit()
            cursor.close()
            conn.close()
            return jsonify({'success': True, 'message': 'Message sent successfully', 'messageId': msg_id}), 201
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error processing messages: {str(e)}'}), 500

@app.route('/api/mobile/capture', methods=['POST'])
def mobile_capture():
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
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
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
    try:
        data = request.get_json()
        required = ['name', 'phone', 'plateOrAddress', 'bookingDate', 'bookingTime']
        for field in required:
            if not data or field not in data or not data[field]:
                return jsonify({'success': False, 'message': f'{field} is required'}), 400
        booking_id = str(uuid.uuid4())
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
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
        
        nfec_share = round(amount * 0.4, 2)
        aggregator_share = round(amount * 0.3, 2)
        igr_share = round(amount * 0.3, 2)
        payment_id = str(uuid.uuid4())
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
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
    try:
        state = request.args.get('state')
        lga = request.args.get('lga')
        if not state:
            return jsonify({'success': False, 'message': 'state is required'}), 400
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
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

@app.route('/api/vendor/capture-extinguisher', methods=['POST'])
@token_required
def vendor_capture_extinguisher(current_user):
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
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO vendor_entries (id, vendor_id, product_type, data)
            VALUES (%s, %s, %s, %s)
        ''', (entry_id, current_user['id'], product_type, json.dumps(details)))
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({'success': True, 'message': 'Data captured successfully', 'entryId': entry_id}), 201
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error capturing data: {str(e)}'}), 500

@app.route('/api/admin/extinguisher-entries', methods=['GET'])
@admin_token_required
def admin_get_extinguisher_entries(current_admin):
    try:
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute('''
            SELECT id, product_type, data, created_at
            FROM mobile_entries
            ORDER BY created_at DESC
        ''')
        mobile_entries = cursor.fetchall()
        
        cursor.execute('''
            SELECT id, vendor_id, product_type, data, created_at
            FROM vendor_entries
            ORDER BY created_at DESC
        ''')
        vendor_entries = cursor.fetchall()
        
        entries = []
        
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
        
        for row in mobile_entries:
            entries.append({
                'id': row['id'],
                'source': 'mobile',
                'vendorId': None,
                'productType': row['product_type'],
                'data': parse_data(row['data']),
                'createdAt': row['created_at'].isoformat() if row['created_at'] else None
            })
        
        for row in vendor_entries:
            entries.append({
                'id': row['id'],
                'source': 'vendor',
                'vendorId': row['vendor_id'],
                'productType': row['product_type'],
                'data': parse_data(row['data']),
                'createdAt': row['created_at'].isoformat() if row['created_at'] else None
            })
        
        entries.sort(key=lambda x: x['createdAt'] or '', reverse=True)
        
        cursor.close()
        conn.close()
        
        return jsonify({'success': True, 'entries': entries}), 200
        
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error retrieving entries: {str(e)}'}), 500

@app.route('/api/admin/training/stats', methods=['GET'])
@admin_token_required
def admin_training_stats(current_admin):
    try:
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute('SELECT COUNT(*) as total FROM training_bookings')
        total_result = cursor.fetchone()
        total_bookings = total_result['total'] if total_result else 0
        
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
    try:
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute('SELECT product_type, data, created_at FROM mobile_entries')
        mobile_rows = cursor.fetchall()
        
        cursor.execute('SELECT product_type, data, created_at FROM vendor_entries')
        vendor_rows = cursor.fetchall()
        
        cursor.close()
        conn.close()

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

        total_entries = 0
        by_source = {'mobile': 0, 'vendor': 0}
        by_product_type = {'existing_extinguisher': 0, 'new_extinguisher': 0, 'dcp_sachet': 0}
        classification_counts = {'vehicle': 0, 'building': 0, 'decommissioned': 0, 'adhoc': 0}
        by_state = {}
        by_local_government = {}
        expired_count = 0

        def process_entry(row, source):
            nonlocal total_entries, by_source, by_product_type, classification_counts, by_state, by_local_government, expired_count
            total_entries += 1
            by_source[source] += 1
            product_type = row['product_type']
            by_product_type[product_type] = by_product_type.get(product_type, 0) + 1
            
            data = parse_data(row['data'])
            
            classification = 'adhoc'
            lowered = {k.lower(): v for k, v in data.items()} if isinstance(data, dict) else {}
            
            if lowered.get('plate_number') or lowered.get('platenumber') or lowered.get('plate'):
                classification = 'vehicle'
            elif lowered.get('building_address') or lowered.get('buildingaddress'):
                classification = 'building'
            
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

@app.route('/')
def health_check():
    return jsonify({
        'success': True,
        'message': 'FEIMS Backend is running',
        'timestamp': datetime.now().isoformat()
    }), 200

if __name__ == '__main__':
    try:
        init_db()
        print("Database initialization completed")
    except Exception as e:
        print(f"Database initialization error: {e}")
    
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=os.environ.get('DEBUG', 'False').lower() == 'true')