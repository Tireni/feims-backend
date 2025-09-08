# vendors.py
from flask import Blueprint, jsonify, request
import mysql.connector
import bcrypt
import jwt
import uuid
from datetime import datetime, timedelta

from utils import token_required, get_db_connection, get_vendor_by_email
from main import app

vendors_bp = Blueprint('vendors', __name__)

# ===================== VENDOR APIs =====================
@vendors_bp.route('/register', methods=['POST'])
def vendor_register():
    try:
        data = request.get_json()
        
        required_fields = ['contactName', 'email', 'phone', 'businessAddress', 'state', 'localGovernment', 'category', 'password']
        for field in required_fields:
            if not data.get(field):
                return jsonify({
                    'success': False,
                    'message': f'{field} is required'
                }), 400
        
        if data['category'] not in ['manufacturer', 'servicing_vendor', 'contractor']:
            return jsonify({
                'success': False,
                'message': 'Invalid category'
            }), 400
        
        # Check if vendor already exists
        existing_vendor = get_vendor_by_email(data['email'])
        if existing_vendor:
            return jsonify({
                'success': False,
                'message': 'Vendor with this email already exists'
            }), 409
        
        # Hash password
        hashed_password = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor()
        
        try:
            vendor_id = str(uuid.uuid4())
            cursor.execute('''
                INSERT INTO vendors (id, contact_name, email, phone, business_address, state, local_government, category, password_hash)
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
                hashed_password
            ))
            
            conn.commit()
            
            return jsonify({
                'success': True,
                'message': 'Vendor registration submitted for approval'
            }), 201
            
        except Exception as e:
            conn.rollback()
            from utils import logger
            logger.error(f"Error registering vendor: {e}")
            return jsonify({
                'success': False,
                'message': f'Error registering vendor: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        from utils import logger
        logger.error(f"Error in vendor_register: {e}")
        return jsonify({
            'success': False,
            'message': f'Error registering vendor: {str(e)}'
        }), 500

@vendors_bp.route('/login', methods=['POST'])
def vendor_login():
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
                'message': 'Invalid credentials'
            }), 401
        
        if vendor['status'] != 'approved':
            return jsonify({
                'success': False,
                'message': 'Vendor account not yet approved'
            }), 403
        
        if not bcrypt.checkpw(data['password'].encode('utf-8'), vendor['password_hash'].encode('utf-8')):
            return jsonify({
                'success': False,
                'message': 'Invalid credentials'
            }), 401
        
        token = jwt.encode({
            'vendor_id': vendor['id'],
            'exp': datetime.now() + timedelta(hours=24)
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
                'businessAddress': vendor['business_address'],
                'state': vendor['state'],
                'localGovernment': vendor['local_government'],
                'category': vendor['category']
            }
        }), 200
        
    except Exception as e:
        from utils import logger
        logger.error(f"Error in vendor_login: {e}")
        return jsonify({
            'success': False,
            'message': f'Error logging in: {str(e)}'
        }), 500

@vendors_bp.route('/dashboard', methods=['GET'])
@token_required
def vendor_dashboard(current_vendor):
    try:
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor(dictionary=True)
        
        try:
            # Get vendor stats
            cursor.execute('SELECT COUNT(*) as qr_count FROM qr_codes WHERE vendor_id = %s', (current_vendor['id'],))
            qr_count = cursor.fetchone()['qr_count']
            
            cursor.execute('SELECT COUNT(*) as sales_count FROM sales WHERE vendor_id = %s', (current_vendor['id'],))
            sales_count = cursor.fetchone()['sales_count']
            
            cursor.execute('SELECT COUNT(*) as services_count FROM services WHERE vendor_id = %s', (current_vendor['id'],))
            services_count = cursor.fetchone()['services_count']
            
            cursor.execute('SELECT COUNT(*) as decommissions_count FROM decommissions WHERE vendor_id = %s', (current_vendor['id'],))
            decommissions_count = cursor.fetchone()['decommissions_count']
            
            return jsonify({
                'success': True,
                'stats': {
                    'qrCodes': qr_count,
                    'sales': sales_count,
                    'services': services_count,
                    'decommissions': decommissions_count
                }
            }), 200
            
        except Exception as e:
            from utils import logger
            logger.error(f"Error fetching vendor dashboard: {e}")
            return jsonify({
                'success': False,
                'message': f'Error fetching dashboard: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        from utils import logger
        logger.error(f"Error in vendor_dashboard: {e}")
        return jsonify({
            'success': False,
            'message': f'Error fetching dashboard: {str(e)}'
        }), 500

@vendors_bp.route('/qr-codes', methods=['GET'])
@token_required
def vendor_get_qr_codes(current_vendor):
    try:
        status = request.args.get('status')
        
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor(dictionary=True)
        
        try:
            if status and status in ['active', 'inactive', 'pending']:
                cursor.execute('''
                    SELECT id, product_type, size, type, status, created_at, activated_at
                    FROM qr_codes 
                    WHERE vendor_id = %s AND status = %s
                    ORDER BY created_at DESC
                ''', (current_vendor['id'], status))
            else:
                cursor.execute('''
                    SELECT id, product_type, size, type, status, created_at, activated_at
                    FROM qr_codes 
                    WHERE vendor_id = %s
                    ORDER BY created_at DESC
                ''', (current_vendor['id'],))
            
            qr_codes = cursor.fetchall()
            
            return jsonify({
                'success': True,
                'qrCodes': qr_codes
            }), 200
            
        except Exception as e:
            from utils import logger
            logger.error(f"Error fetching QR codes: {e}")
            return jsonify({
                'success': False,
                'message': f'Error fetching QR codes: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        from utils import logger
        logger.error(f"Error in vendor_get_qr_codes: {e}")
        return jsonify({
            'success': False,
            'message': f'Error fetching QR codes: {str(e)}'
        }), 500

@vendors_bp.route('/generate-qr', methods=['POST'])
@token_required
def vendor_generate_qr(current_vendor):
    try:
        data = request.get_json()
        
        required_fields = ['productType', 'size', 'type']
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
            qr_id = str(uuid.uuid4())
            cursor.execute('''
                INSERT INTO qr_codes (id, vendor_id, product_type, size, type, qr_image)
                VALUES (%s, %s, %s, %s, %s, %s)
            ''', (
                qr_id,
                current_vendor['id'],
                data['productType'],
                data['size'],
                data['type'],
                f"https://api.qrserver.com/v1/create-qr-code/?size=150x150&data={qr_id}"
            ))
            
            conn.commit()
            
            return jsonify({
                'success': True,
                'message': 'QR code generated successfully',
                'qrCode': {
                    'id': qr_id,
                    'imageUrl': f"https://api.qrserver.com/v1/create-qr-code/?size=150x150&data={qr_id}"
                }
            }), 201
            
        except Exception as e:
            conn.rollback()
            from utils import logger
            logger.error(f"Error generating QR code: {e}")
            return jsonify({
                'success': False,
                'message': f'Error generating QR code: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        from utils import logger
        logger.error(f"Error in vendor_generate_qr: {e}")
        return jsonify({
            'success': False,
            'message': f'Error generating QR code: {str(e)}'
        }), 500

@vendors_bp.route('/sales', methods=['POST'])
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

@vendors_bp.route('/services', methods=['POST'])
@token_required
def vendor_record_service(current_vendor):
    try:
        data = request.get_json()
        
        required_fields = ['qrCodeId', 'serviceType']
        for field in required_fields:
            if not data.get(field):
                return jsonify({
                    'success': False,
                    'message': f'{field} is required'
                }), 400
        
        if data['serviceType'] not in ['refill', 'inspection', 'maintenance', 'repair', 'installation']:
            return jsonify({
                'success': False,
                'message': 'Invalid service type'
            }), 400
        
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor()
        
        try:
            service_id = str(uuid.uuid4())
            cursor.execute('''
                INSERT INTO services (id, vendor_id, qr_code_id, service_type, description, amount, customer_name, customer_phone, customer_email, customer_address)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ''', (
                service_id,
                current_vendor['id'],
                data['qrCodeId'],
                data['serviceType'],
                data.get('description'),
                data.get('amount'),
                data.get('customerName'),
                data.get('customerPhone'),
                data.get('customerEmail'),
                data.get('customerAddress')
            ))
            
            conn.commit()
            
            return jsonify({
                'success': True,
                'message': 'Service recorded successfully'
            }), 201
            
        except Exception as e:
            conn.rollback()
            from utils import logger
            logger.error(f"Error recording service: {e}")
            return jsonify({
                'success': False,
                'message': f'Error recording service: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        from utils import logger
        logger.error(f"Error in vendor_record_service: {e}")
        return jsonify({
            'success': False,
            'message': f'Error recording service: {str(e)}'
        }), 500

@vendors_bp.route('/decommission', methods=['POST'])
@token_required
def vendor_record_decommission(current_vendor):
    try:
        data = request.get_json()
        
        required_fields = ['qrCodeId', 'reason', 'disposalMethod', 'disposalDate']
        for field in required_fields:
            if not data.get(field):
                return jsonify({
                    'success': False,
                    'message': f'{field} is required'
                }), 400
        
        if data['reason'] not in ['expired', 'damaged', 'faulty', 'recall', 'other']:
            return jsonify({
                'success': False,
                'message': 'Invalid reason'
            }), 400
        
        if data['disposalMethod'] not in ['recycled', 'disposed', 'returned', 'other']:
            return jsonify({
                'success': False,
                'message': 'Invalid disposal method'
            }), 400
        
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor()
        
        try:
            decommission_id = str(uuid.uuid4())
            cursor.execute('''
                INSERT INTO decommissions (id, vendor_id, qr_code_id, reason, disposal_method, disposal_date, notes, evidence_path)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            ''', (
                decommission_id,
                current_vendor['id'],
                data['qrCodeId'],
                data['reason'],
                data['disposalMethod'],
                data['disposalDate'],
                data.get('notes'),
                data.get('evidencePath')
            ))
            
            conn.commit()
            
            return jsonify({
                'success': True,
                'message': 'Decommission recorded successfully'
            }), 201
            
        except Exception as e:
            conn.rollback()
            from utils import logger
            logger.error(f"Error recording decommission: {e}")
            return jsonify({
                'success': False,
                'message': f'Error recording decommission: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        from utils import logger
        logger.error(f"Error in vendor_record_decommission: {e}")
        return jsonify({
            'success': False,
            'message': f'Error recording decommission: {str(e)}'
        }), 500

@vendors_bp.route('/profile', methods=['GET'])
@token_required
def vendor_get_profile(current_vendor):
    try:
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor(dictionary=True)
        
        try:
            cursor.execute('''
                SELECT id, contact_name, email, phone, business_address, state, local_government, category, status, created_at
                FROM vendors 
                WHERE id = %s
            ''', (current_vendor['id'],))
            
            vendor = cursor.fetchone()
            
            return jsonify({
                'success': True,
                'vendor': vendor
            }), 200
            
        except Exception as e:
            from utils import logger
            logger.error(f"Error fetching vendor profile: {e}")
            return jsonify({
                'success': False,
                'message': f'Error fetching profile: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        from utils import logger
        logger.error(f"Error in vendor_get_profile: {e}")
        return jsonify({
            'success': False,
            'message': f'Error fetching profile: {str(e)}'
        }), 500

@vendors_bp.route('/profile', methods=['PUT'])
@token_required
def vendor_update_profile(current_vendor):
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                'success': False,
                'message': 'No data provided for update'
            }), 400
        
        allowed_fields = ['contactName', 'phone', 'businessAddress', 'state', 'localGovernment']
        update_fields = {}
        
        for field in allowed_fields:
            if field in data:
                db_field = field[0].lower() + field[1:]
                update_fields[db_field] = data[field]
        
        if not update_fields:
            return jsonify({
                'success': False,
                'message': 'No valid fields to update'
            }), 400
        
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor()
        
        try:
            set_clause = ', '.join([f"{field} = %s" for field in update_fields.keys()])
            values = list(update_fields.values())
            values.append(current_vendor['id'])
            
            cursor.execute(f'''
                UPDATE vendors 
                SET {set_clause}
                WHERE id = %s
            ''', values)
            
            conn.commit()
            
            return jsonify({
                'success': True,
                'message': 'Profile updated successfully'
            }), 200
            
        except Exception as e:
            conn.rollback()
            from utils import logger
            logger.error(f"Error updating vendor profile: {e}")
            return jsonify({
                'success': False,
                'message': f'Error updating profile: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        from utils import logger
        logger.error(f"Error in vendor_update_profile: {e}")
        return jsonify({
            'success': False,
            'message': f'Error updating profile: {str(e)}'
        }), 500