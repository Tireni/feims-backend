# mobile_vendors.py
from flask import Blueprint, jsonify, request
import mysql.connector
import bcrypt
import jwt
import uuid
from datetime import datetime, timedelta

from utils import token_required, get_db_connection
from flask import current_app
import json
import logging


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


mobile_vendors_bp = Blueprint('mobile_vendors', __name__)

# ===================== MOBILE VENDOR APIs =====================
@mobile_vendors_bp.route('/vendors/register', methods=['POST'])
def mobile_vendor_register():
    try:
        data = request.get_json()
        
        required_fields = ['fullName', 'username', 'password']
        for field in required_fields:
            if not data.get(field):
                return jsonify({
                    'success': False,
                    'message': f'{field} is required'
                }), 400
        
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor(dictionary=True)
        
        try:
            # Check if username already exists
            cursor.execute('SELECT id FROM mobile_vendors WHERE username = %s', (data['username'],))
            if cursor.fetchone():
                return jsonify({
                    'success': False,
                    'message': 'Username already exists'
                }), 409
            
            # Hash password
            hashed_password = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            
            vendor_id = str(uuid.uuid4())
            cursor.execute('''
                INSERT INTO mobile_vendors (id, full_name, username, password_hash)
                VALUES (%s, %s, %s, %s)
            ''', (
                vendor_id,
                data['fullName'],
                data['username'],
                hashed_password
            ))
            
            conn.commit()
            
            return jsonify({
                'success': True,
                'message': 'Mobile vendor registered successfully'
            }), 201
            
        except Exception as e:
            conn.rollback()
            from utils import logger
            logger.error(f"Error registering mobile vendor: {e}")
            return jsonify({
                'success': False,
                'message': f'Error registering mobile vendor: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        from utils import logger
        logger.error(f"Error in mobile_vendor_register: {e}")
        return jsonify({
            'success': False,
            'message': f'Error registering mobile vendor: {str(e)}'
        }), 500

@mobile_vendors_bp.route('/vendors/login', methods=['POST'])
def mobile_vendor_login():
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
            cursor.execute('SELECT id, full_name, username, password_hash FROM mobile_vendors WHERE username = %s', (data['username'],))
            vendor = cursor.fetchone()
            
            if not vendor:
                return jsonify({
                    'success': False,
                    'message': 'Invalid credentials'
                }), 401
            
            if not bcrypt.checkpw(data['password'].encode('utf-8'), vendor['password_hash'].encode('utf-8')):
                return jsonify({
                    'success': False,
                    'message': 'Invalid credentials'
                }), 401
            
            token = jwt.encode({
                'vendor_id': vendor['id'],
                'is_mobile': True,
                'exp': datetime.now() + timedelta(hours=24)
            }, current_app.config['SECRET_KEY'], algorithm="HS256")

            
            return jsonify({
                'success': True,
                'message': 'Login successful',
                'token': token,
                'vendor': {
                    'id': vendor['id'],
                    'fullName': vendor['full_name'],
                    'username': vendor['username']
                }
            }), 200
            
        except Exception as e:
            from utils import logger
            logger.error(f"Error in mobile vendor login: {e}")
            return jsonify({
                'success': False,
                'message': f'Error logging in: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        from utils import logger
        logger.error(f"Error in mobile_vendor_login: {e}")
        return jsonify({
            'success': False,
            'message': f'Error logging in: {str(e)}'
        }), 500

@mobile_vendors_bp.route('/register', methods=['POST'])
def training_booking():
    try:
        data = request.get_json()
        
        required_fields = ['name', 'phone', 'plateOrAddress', 'bookingDate', 'bookingTime']
        for field in required_fields:
            if not data.get(field):
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
            
            return jsonify({
                'success': True,
                'message': 'Training booking submitted successfully'
            }), 201
            
        except Exception as e:
            conn.rollback()
            from utils import logger
            logger.error(f"Error creating training booking: {e}")
            return jsonify({
                'success': False,
                'message': f'Error creating training booking: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        from utils import logger
        logger.error(f"Error in training_booking: {e}")
        return jsonify({
            'success': False,
            'message': f'Error creating training booking: {str(e)}'
        }), 500
    

@mobile_vendors_bp.route('/entry', methods=['POST'])
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
    
@mobile_vendors_bp.route('/entries', methods=['POST'])
@token_required
def vendor_capture_data(current_vendor):
    try:
        data = request.get_json()
        
        required_fields = ['productType', 'data']
        for field in required_fields:
            if not data.get(field):
                return jsonify({
                    'success': False,
                    'message': f'{field} is required'
                }), 400
        
        if data['productType'] not in ['existing_extinguisher', 'new_extinguisher', 'dcp_sachet']:
            return jsonify({
                'success': False,
                'message': 'Invalid product type'
            }), 400
        
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor()
        
        try:
            entry_id = str(uuid.uuid4())
            
            # Extract data for QR code creation
            product_data = data['data']
            
            # Create QR code entry first
            qr_code_id = str(uuid.uuid4())
            cursor.execute('''
                INSERT INTO qr_codes (id, vendor_id, product_type, size, type, qr_image, status)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            ''', (
                qr_code_id,
                current_vendor['id'],
                data['productType'],
                product_data.get('size', ''),
                product_data.get('type', ''),
                '',  # Empty QR image for now
                'inactive'
            ))
            
            # Create the vendor entry
            cursor.execute('''
                INSERT INTO vendor_entries (id, vendor_id, product_type, data)
                VALUES (%s, %s, %s, %s)
            ''', (
                entry_id,
                current_vendor['id'],
                data['productType'],
                json.dumps(data['data'])
            ))
            
            conn.commit()
            
            return jsonify({
                'success': True,
                'message': 'Data captured successfully',
                'qrCodeId': qr_code_id,
                'entryId': entry_id
            }), 201
            
        except Exception as e:
            conn.rollback()
            from utils import logger
            logger.error(f"Error capturing data: {e}")
            return jsonify({
                'success': False,
                'message': f'Error capturing data: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        from utils import logger
        logger.error(f"Error in vendor_capture_data: {e}")
        return jsonify({
            'success': False,
            'message': f'Error capturing data: {str(e)}'
        }), 500

@mobile_vendors_bp.route('/activate-qr', methods=['POST'])
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

@mobile_vendors_bp.route('/sales', methods=['POST'])
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



@mobile_vendors_bp.route('/fireentries', methods=['POST'])
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