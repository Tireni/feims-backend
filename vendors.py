
import os
from flask import Blueprint, jsonify, request, current_app
import uuid
import bcrypt
import jwt
import qrcode
import io, base64, json
from functools import wraps
from datetime import datetime, timedelta, timezone
import logging

from utils import get_db_connection

logger = logging.getLogger(__name__)
vendors_bp = Blueprint('vendors', __name__)

# Paystack Configuration

UNIT_PRICE_NGN = 200.00  # ₦200 per sticker

def vendor_token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            parts = request.headers['Authorization'].split()
            if len(parts) == 2 and parts[0].lower() == 'bearer':
                token = parts[1]

        if not token:
            return jsonify({'success': False, 'message': 'Token is missing'}), 401
        try:
            data = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=["HS256"])
            vendor_id = data.get('vendor_id')
            if not vendor_id:
                return jsonify({'success': False, 'message': 'Invalid token'}), 401
            vendor = _get_vendor_by_id(vendor_id)
            if not vendor:
                return jsonify({'success': False, 'message': 'Vendor not found'}), 401
            return f(vendor, *args, **kwargs)
        except jwt.ExpiredSignatureError:
            return jsonify({'success': False, 'message': 'Token expired'}), 401
        except Exception as e:
            return jsonify({'success': False, 'message': f'Authentication error: {str(e)}'}), 401
    return decorated

def _get_vendor_by_email(email: str):
    conn = get_db_connection()
    if conn is None:
        return None
    cur = conn.cursor(dictionary=True)
    try:
        cur.execute("SELECT * FROM vendors WHERE email=%s LIMIT 1", (email,))
        return cur.fetchone()
    finally:
        cur.close(); conn.close()

def _get_vendor_by_id(vendor_id: str):
    conn = get_db_connection()
    if conn is None:
        return None
    cur = conn.cursor(dictionary=True)
    try:
        cur.execute("SELECT * FROM vendors WHERE id=%s LIMIT 1", (vendor_id,))
        return cur.fetchone()
    finally:
        cur.close(); conn.close()



# =========================
# Vendor — Auth endpoints
# =========================
@vendors_bp.route('/register', methods=['POST'])
def vendor_register():
    """
    Self-serve vendor registration (auto-approve). Returns JWT token immediately.
    """
    try:
        data = request.get_json() or {}
        required = ['contactName','email','phone','businessAddress','state','localGovernment','category','password']
        for f in required:
            if not data.get(f):
                return jsonify({'success': False, 'message': f'{f} is required'}), 400

        if data['category'] not in ['manufacturer', 'servicing_vendor', 'contractor']:
            return jsonify({'success': False, 'message': 'Invalid category'}), 400

        if _get_vendor_by_email(data['email']):
            return jsonify({'success': False, 'message': 'Vendor with this email already exists'}), 409

        pwd_hash = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
        cur = conn.cursor()
        try:
            vid = str(uuid.uuid4())
            cur.execute('''
                INSERT INTO vendors
                (id, contact_name, email, phone, business_address, state, local_government, category, password_hash, status)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,'approved')
            ''', (
                vid, data['contactName'], data['email'], data['phone'], data['businessAddress'],
                data['state'], data['localGovernment'], data['category'], pwd_hash
            ))
            conn.commit()
        except Exception as e:
            conn.rollback()
            return jsonify({'success': False, 'message': f'Error registering vendor: {str(e)}'}), 500
        finally:
            cur.close(); conn.close()

        token = jwt.encode(
            {'vendor_id': vid, 'exp': datetime.now() + timedelta(hours=24)},
            current_app.config['SECRET_KEY'], algorithm="HS256"
        )
        return jsonify({
            'success': True,
            'message': 'Vendor registered and approved',
            'token': token,
            'vendor': {
                'id': vid,
                'contactName': data['contactName'],
                'email': data['email'],
                'phone': data['phone'],
                'businessAddress': data['businessAddress'],
                'state': data['state'],
                'localGovernment': data['localGovernment'],
                'category': data['category']
            }
        }), 201

    except Exception as e:
        return jsonify({'success': False, 'message': f'Error in vendor_register: {str(e)}'}), 500

@vendors_bp.route('/login', methods=['POST'])
def vendor_login():
    """
    Login (no approval gate).
    """
    try:
        data = request.get_json() or {}
        email = data.get('email'); password = data.get('password')
        if not email or not password:
            return jsonify({'success': False, 'message': 'Email and password are required'}), 400

        vendor = _get_vendor_by_email(email)
        if not vendor or not bcrypt.checkpw(password.encode('utf-8'), vendor['password_hash'].encode('utf-8')):
            return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

        token = jwt.encode(
            {'vendor_id': vendor['id'], 'exp': datetime.now() + timedelta(hours=24)},
            current_app.config['SECRET_KEY'], algorithm="HS256"
        )
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
        return jsonify({'success': False, 'message': f'Error logging in: {str(e)}'}), 500

# =========================
# Vendor — Dashboard stats
# =========================
@vendors_bp.route('/dashboard-stats', methods=['GET'])
@vendor_token_required
def vendor_dashboard_stats(current_vendor):
    """
    Returns ONLY vendor QR stats (total + by status).
    """
    try:
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
        cur = conn.cursor(dictionary=True)
        try:
            cur.execute('SELECT COUNT(*) AS total FROM qr_codes WHERE vendor_id=%s', (current_vendor['id'],))
            total = cur.fetchone()['total'] if cur.rowcount is not None else 0

            cur.execute('SELECT status, COUNT(*) AS c FROM qr_codes WHERE vendor_id=%s GROUP BY status', (current_vendor['id'],))
            by = {'active': 0, 'inactive': 0, 'pending': 0}
            for row in cur.fetchall():
                s = row['status']
                if s in by:
                    by[s] = row['c']

            return jsonify({'success': True, 'stats': {'total': total, 'byStatus': by}}), 200
        finally:
            cur.close(); conn.close()
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error fetching stats: {str(e)}'}), 500


@vendors_bp.route('/qr/generate-after-payment', methods=['POST'])
@vendor_token_required
def generate_qr_after_payment(current_vendor):
    """
    Generate QR codes after payment has been confirmed on frontend
    """
    try:
        data = request.get_json() or {}
        reference = data.get('reference')
        form_data = data.get('form_data')
        
        if not reference or not form_data:
            return jsonify({'success': False, 'message': 'Reference and form data are required'}), 400

        # Check if this request has already been processed
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cur = conn.cursor(dictionary=True)
        try:
            cur.execute("SELECT * FROM qr_purchase_requests WHERE trace_id=%s LIMIT 1", (reference,))
            pr = cur.fetchone()
            
            if pr and pr['status'] == 'paid':
                return jsonify({'success': True, 'message': 'QR codes already generated'}), 200
                
            # Create purchase request record if it doesn't exist
            if not pr:
                quantity = int(form_data.get('quantity', 1))
                pr_id = str(uuid.uuid4())
                cur.execute('''
                    INSERT INTO qr_purchase_requests
                    (id, vendor_id, product_type, size, type, quantity, unit_amount, total_amount, form_payload, trace_id, status)
                    VALUES (%s,%s,'new_extinguisher',%s,%s,%s,%s,%s,%s,%s,'pending')
                ''', (
                    pr_id, current_vendor['id'], form_data['size'], form_data['type'], quantity,
                    UNIT_PRICE_NGN, quantity * UNIT_PRICE_NGN, json.dumps(form_data), reference
                ))
            
            # Generate QR codes
            cur2 = conn.cursor()
            generated_ids = []
            
            for _ in range(int(form_data['quantity'])):
                qr_id = str(uuid.uuid4())
                qr_url = f"https://nfdrc.ng/feims/scan.php/{qr_id}"

                qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=10, border=4)
                qr.add_data(qr_url); qr.make(fit=True)
                img = qr.make_image(fill_color="#ff7b00", back_color="white")
                buf = io.BytesIO(); img.save(buf, format="PNG")
                img_b64 = base64.b64encode(buf.getvalue()).decode('utf-8')

                # Insert into qr_codes
                cur2.execute('''
                    INSERT INTO qr_codes (id, vendor_id, product_type, size, type, qr_image, status)
                    VALUES (%s,%s,'new_extinguisher',%s,%s,%s,'inactive')
                ''', (qr_id, current_vendor['id'], form_data['size'], form_data['type'], img_b64))

                # Insert into new_extinguishers
                ne_id = str(uuid.uuid4())
                cur2.execute('''
                    INSERT INTO new_extinguishers
                    (id, qr_code_id, manufacturer_name, son_number, ncs_receipt_number, ffs_fat_id, distributor_name,
                     manufacturing_date, expiry_date, engraved_id, phone_number, state, local_government)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ''', (
                    ne_id, qr_id,
                    form_data['manufacturerName'], form_data['sonNumber'], form_data['ncsReceiptNumber'], form_data['ffsFATId'],
                    form_data['distributorName'], form_data['manufacturingDate'], form_data['expiryDate'], form_data['engravedId'],
                    form_data['phoneNumber'], form_data['state'], form_data['localGovernment']
                ))

                generated_ids.append(qr_id)

            # Mark request as paid
            cur2.execute("UPDATE qr_purchase_requests SET status='paid' WHERE trace_id=%s", (reference,))
            conn.commit()
            cur2.close()

            logger.info(f"Successfully generated {len(generated_ids)} QR codes for reference {reference}")
            
            return jsonify({
                'success': True, 
                'message': f'{len(generated_ids)} QR codes generated successfully',
                'qr_codes_generated': len(generated_ids)
            }), 200
            
        except Exception as e:
            conn.rollback()
            logger.error(f"QR generation error: {str(e)}")
            return jsonify({'success': False, 'message': f'QR generation error: {str(e)}'}), 500
        finally:
            cur.close(); conn.close()
            
    except Exception as e:
        logger.error(f"Error in generate_qr_after_payment: {str(e)}")
        return jsonify({'success': False, 'message': f'Error generating QR codes: {str(e)}'}), 500
    

# =========================
# Vendor — QR Code Management
# =========================
@vendors_bp.route('/qr-codes', methods=['GET'])
@vendor_token_required
def get_vendor_qr_codes(current_vendor):
    """
    Get all QR codes for the current vendor with pagination
    """
    try:
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 20))
        status_filter = request.args.get('status')
        
        offset = (page - 1) * per_page
        
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cur = conn.cursor(dictionary=True)
        
        try:
            # Build query with optional status filter
            query = '''
                SELECT id, product_type, size, type, status, created_at, activated_at
                FROM qr_codes 
                WHERE vendor_id = %s
            '''
            params = [current_vendor['id']]
            
            if status_filter and status_filter in ['active', 'inactive', 'pending']:
                query += ' AND status = %s'
                params.append(status_filter)
                
            query += ' ORDER BY created_at DESC LIMIT %s OFFSET %s'
            params.extend([per_page, offset])
            
            cur.execute(query, params)
            qr_codes = cur.fetchall()
            
            # Get total count for pagination
            count_query = 'SELECT COUNT(*) as total FROM qr_codes WHERE vendor_id = %s'
            count_params = [current_vendor['id']]
            
            if status_filter and status_filter in ['active', 'inactive', 'pending']:
                count_query += ' AND status = %s'
                count_params.append(status_filter)
                
            cur.execute(count_query, count_params)
            total_count = cur.fetchone()['total']
            
            return jsonify({
                'success': True,
                'qr_codes': qr_codes,
                'pagination': {
                    'page': page,
                    'per_page': per_page,
                    'total': total_count,
                    'pages': (total_count + per_page - 1) // per_page
                }
            }), 200
            
        except Exception as e:
            logger.error(f"Error fetching QR codes: {str(e)}")
            return jsonify({'success': False, 'message': f'Error fetching QR codes: {str(e)}'}), 500
        finally:
            cur.close()
            conn.close()
            
    except Exception as e:
        logger.error(f"Error in get_vendor_qr_codes: {str(e)}")
        return jsonify({'success': False, 'message': f'Error fetching QR codes: {str(e)}'}), 500

@vendors_bp.route('/qr-code/<qr_id>/image', methods=['GET'])
@vendor_token_required
def get_qr_code_image(current_vendor, qr_id):
    """
    Get the QR code image for a specific QR code ID
    """
    try:
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cur = conn.cursor(dictionary=True)
        
        try:
            # Verify the QR code belongs to the vendor
            cur.execute('''
                SELECT qr_image FROM qr_codes 
                WHERE id = %s AND vendor_id = %s
            ''', (qr_id, current_vendor['id']))
            
            qr_code = cur.fetchone()
            
            if not qr_code:
                return jsonify({'success': False, 'message': 'QR code not found or access denied'}), 404
                
            return jsonify({
                'success': True,
                'qr_image': qr_code['qr_image']
            }), 200
            
        except Exception as e:
            logger.error(f"Error fetching QR image: {str(e)}")
            return jsonify({'success': False, 'message': f'Error fetching QR image: {str(e)}'}), 500
        finally:
            cur.close()
            conn.close()
            
    except Exception as e:
        logger.error(f"Error in get_qr_code_image: {str(e)}")
        return jsonify({'success': False, 'message': f'Error fetching QR image: {str(e)}'}), 500

@vendors_bp.route('/qr-code/<qr_id>/details', methods=['GET'])
@vendor_token_required
def get_qr_code_details(current_vendor, qr_id):
    """
    Get detailed information about a specific QR code
    """
    try:
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cur = conn.cursor(dictionary=True)
        
        try:
            # Verify the QR code belongs to the vendor and get basic info
            cur.execute('''
                SELECT id, product_type, size, type, status, created_at, activated_at
                FROM qr_codes 
                WHERE id = %s AND vendor_id = %s
            ''', (qr_id, current_vendor['id']))
            
            qr_code = cur.fetchone()
            
            if not qr_code:
                return jsonify({'success': False, 'message': 'QR code not found or access denied'}), 404
            
            # Get product-specific information
            product_info = {}
            
            if qr_code['product_type'] == 'existing_extinguisher':
                cur.execute('''
                    SELECT plate_number, building_address, manufacturing_date, expiry_date,
                           engraved_id, phone_number, manufacturer_name, state, local_government
                    FROM existing_extinguishers WHERE qr_code_id = %s
                ''', (qr_id,))
                product_info = cur.fetchone()
                
            elif qr_code['product_type'] == 'new_extinguisher':
                cur.execute('''
                    SELECT manufacturer_name, son_number, ncs_receipt_number, ffs_fat_id,
                           distributor_name, manufacturing_date, expiry_date, engraved_id,
                           phone_number, state, local_government
                    FROM new_extinguishers WHERE qr_code_id = %s
                ''', (qr_id,))
                product_info = cur.fetchone()
                
            elif qr_code['product_type'] == 'dcp_sachet':
                cur.execute('''
                    SELECT manufacturer_name, son_number, ncs_receipt_number, ffs_fat_id,
                           distributor_name, packaging_company, manufacturing_date, expiry_date,
                           batch_lot_id, phone_number, state, local_government
                    FROM dcp_sachets WHERE qr_code_id = %s
                ''', (qr_id,))
                product_info = cur.fetchone()
            
            return jsonify({
                'success': True,
                'qr_code': qr_code,
                'product_info': product_info
            }), 200
            
        except Exception as e:
            logger.error(f"Error fetching QR details: {str(e)}")
            return jsonify({'success': False, 'message': f'Error fetching QR details: {str(e)}'}), 500
        finally:
            cur.close()
            conn.close()
            
    except Exception as e:
        logger.error(f"Error in get_qr_code_details: {str(e)}")
        return jsonify({'success': False, 'message': f'Error fetching QR details: {str(e)}'}), 500