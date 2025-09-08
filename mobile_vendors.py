# mobile_vendors.py
from flask import Blueprint, jsonify, request
import mysql.connector
import bcrypt
import jwt
import uuid
from datetime import datetime, timedelta

from utils import token_required, get_db_connection, get_app


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
            }, get_app().config['SECRET_KEY'], algorithm="HS256")
            
            
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
def mobile_capture_data():
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
                'message': 'Data captured successfully'
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
        logger.error(f"Error in mobile_capture_data: {e}")
        return jsonify({
            'success': False,
            'message': f'Error capturing data: {str(e)}'
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
                'message': 'Data captured successfully'
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
def vendor_activate_qr(current_vendor):
    try:
        data = request.get_json()
        
        if not data or not data.get('qrId'):
            return jsonify({
                'success': False,
                'message': 'QR ID is required'
            }), 400
        
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor()
        
        try:
            # Check if QR code exists and belongs to this vendor
            cursor.execute('SELECT id FROM qr_codes WHERE id = %s AND vendor_id = %s', (data['qrId'], current_vendor['id']))
            if not cursor.fetchone():
                return jsonify({
                    'success': False,
                    'message': 'QR code not found or does not belong to this vendor'
                }), 404
            
            # Activate the QR code
            cursor.execute('UPDATE qr_codes SET status = "active", activated_at = NOW() WHERE id = %s', (data['qrId'],))
            
            conn.commit()
            
            return jsonify({
                'success': True,
                'message': 'QR code activated successfully'
            }), 200
            
        except Exception as e:
            conn.rollback()
            from utils import logger
            logger.error(f"Error activating QR code: {e}")
            return jsonify({
                'success': False,
                'message': f'Error activating QR code: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        from utils import logger
        logger.error(f"Error in vendor_activate_qr: {e}")
        return jsonify({
            'success': False,
            'message': f'Error activating QR code: {str(e)}'
        }), 500

@mobile_vendors_bp.route('/sales', methods=['POST'])
@token_required
def vendor_record_sale(current_vendor):
    try:
        data = request.get_json()
        
        required_fields = ['productType', 'quantity', 'amount', 'customerName', 'customerPhone', 'paymentMethod']
        for field in required_fields:
            if not data.get(field):
                return jsonify({
                    'success': False,
                    'message': f'{field} is required'
                }), 400
        
        if data['productType'] not in ['extinguisher', 'dcp', 'accessory', 'service']:
            return jsonify({
                'success': False,
                'message': 'Invalid product type'
            }), 400
        
        if data['paymentMethod'] not in ['cash', 'transfer', 'card', 'pos']:
            return jsonify({
                'success': False,
                'message': 'Invalid payment method'
            }), 400
        
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor()
        
        try:
            sale_id = str(uuid.uuid4())
            cursor.execute('''
                INSERT INTO sales (id, vendor_id, product_type, quantity, amount, customer_name, customer_phone, customer_email, customer_address, payment_method)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ''', (
                sale_id,
                current_vendor['id'],
                data['productType'],
                data['quantity'],
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
                'message': 'Sale recorded successfully'
            }), 201
            
        except Exception as e:
            conn.rollback()
            from utils import logger
            logger.error(f"Error recording sale: {e}")
            return jsonify({
                'success': False,
                'message': f'Error recording sale: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        from utils import logger
        logger.error(f"Error in vendor_record_sale: {e}")
        return jsonify({
            'success': False,
            'message': f'Error recording sale: {str(e)}'
        }), 500