import mysql.connector
import mysql.connector.pooling
import os
import logging
import bcrypt
import jwt
from functools import wraps
from flask import jsonify, request, current_app
from datetime import datetime, timedelta, timezone
logger = logging.getLogger(__name__)

# Database configuration
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

# Admin configuration
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'adminpass')

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
            
            # Use current_app instead of get_app()
            data = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=["HS256"])
            
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

# Admin token required decorator
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
            data = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=["HS256"])
            if data.get('role') != 'admin':
                return jsonify({'success': False, 'message': 'Admin privileges required'}), 403
            current_admin = {'username': data.get('username')}
        except Exception as e:
            logger.error(f"Admin token validation error: {e}")
            return jsonify({'success': False, 'message': 'Invalid or expired admin token'}), 401
        return f(current_admin, *args, **kwargs)
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
# Database initialization
# Database initialization
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
                type VARCHAR(20) NOT NULL,
                qr_image TEXT NOT NULL,
                status ENUM('active', 'inactive', 'pending') DEFAULT 'inactive',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                activated_at TIMESTAMP NULL
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

        # Create table for new fire extinguishers (updated structure)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS new_extinguishers (
                id VARCHAR(255) PRIMARY KEY,
                qr_code_id VARCHAR(255) NOT NULL,
                manufacturer_name VARCHAR(255) NOT NULL,
                son_number VARCHAR(255) NOT NULL,
                ncs_receipt_number VARCHAR(255) NOT NULL,
                ffs_fat_id VARCHAR(255) NOT NULL,
                distributor_name VARCHAR(255) NOT NULL,
                manufacturing_date DATE NOT NULL,
                expiry_date DATE NOT NULL,
                engraved_id VARCHAR(255) NOT NULL,
                phone_number VARCHAR(20) NOT NULL,
                state VARCHAR(100) NOT NULL,
                local_government VARCHAR(100) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                FOREIGN KEY (qr_code_id) REFERENCES qr_codes(id)
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

        # Create sales table
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
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
                FOREIGN KEY (qr_code_id) REFERENCES qr_codes(id) ON DELETE CASCADE
            )
        ''')

        # Create payments table
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
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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

        # Create certifications table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS certifications (
                id VARCHAR(255) PRIMARY KEY,
                vendor_id VARCHAR(255) NOT NULL,
                staff_name VARCHAR(255) NOT NULL,
                staff_email VARCHAR(255),
                staff_phone VARCHAR(20),
                status ENUM('pending','approved','rejected') DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Create compliance_audits table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS compliance_audits (
                id VARCHAR(255) PRIMARY KEY,
                vendor_id VARCHAR(255) NOT NULL,
                audit_date DATE NOT NULL,
                description TEXT,
                result ENUM('pass','fail') NOT NULL,
                notes TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Create notifications table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS notifications (
                id VARCHAR(255) PRIMARY KEY,
                vendor_id VARCHAR(255) NOT NULL,
                title VARCHAR(255) NOT NULL,
                message TEXT NOT NULL,
                category ENUM('anomaly','complaint','compliance','info') NOT NULL,
                is_read BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Create messages table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id VARCHAR(255) PRIMARY KEY,
                vendor_id VARCHAR(255) NOT NULL,
                sender_type ENUM('vendor','admin') NOT NULL,
                content TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Create reports table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS reports (
                id VARCHAR(255) PRIMARY KEY,
                vendor_id VARCHAR(255) NOT NULL,
                subject VARCHAR(255) NOT NULL,
                description TEXT NOT NULL,
                category ENUM('incident','suspicious_vendor','fraud','other') NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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


        # Track vendor QR purchase requests (payment-intent) with status field
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS qr_purchase_requests (
                id VARCHAR(255) PRIMARY KEY,
                vendor_id VARCHAR(255) NOT NULL,
                product_type ENUM('new_extinguisher') NOT NULL,
                size VARCHAR(10) NOT NULL,
                type VARCHAR(20) NOT NULL,
                quantity INT NOT NULL,
                unit_amount DECIMAL(10,2) NOT NULL,
                total_amount DECIMAL(10,2) NOT NULL,
                form_payload JSON NOT NULL,
                trace_id VARCHAR(64) UNIQUE NOT NULL,
                status VARCHAR(20) DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Log CoralPay transactions
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS coralpay_transactions (
                id VARCHAR(255) PRIMARY KEY,
                vendor_id VARCHAR(255) NOT NULL,
                trace_id VARCHAR(64) NOT NULL,
                amount DECIMAL(10,2) NOT NULL,
                response_code VARCHAR(10) NOT NULL,
                raw_payload JSON NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        conn.commit()
        logger.info("Database tables created successfully")

        # Seed training materials if none exist
        cursor.execute('SELECT COUNT(*) FROM training_materials')
        count = cursor.fetchone()[0]
        if count == 0:
            import uuid
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
