# shared.py
from flask import Blueprint, jsonify, request
import mysql.connector
import uuid

from utils import get_db_connection

shared_bp = Blueprint('shared', __name__)

# ===================== SHARED APIs =====================
@shared_bp.route('/scan/<qr_id>', methods=['GET'])
def verify_qr(qr_id):
    try:
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor(dictionary=True)
        
        try:
            # Check if QR code exists
            cursor.execute('''
                SELECT q.id, q.product_type, q.size, q.type, q.status, q.created_at, q.activated_at,
                       COALESCE(v.contact_name, mv.full_name) as vendor_name
                FROM qr_codes q
                LEFT JOIN vendors v ON q.vendor_id = v.id
                LEFT JOIN mobile_vendors mv ON q.vendor_id = mv.id
                WHERE q.id = %s
            ''', (qr_id,))
            
            qr_code = cursor.fetchone()
            
            if not qr_code:
                return jsonify({
                    'success': False,
                    'message': 'QR code not found'
                }), 404
            
            # Get product details based on product type
            product_details = None
            if qr_code['product_type'] == 'existing_extinguisher':
                cursor.execute('''
                    SELECT * FROM existing_extinguishers 
                    WHERE qr_code_id = %s
                ''', (qr_id,))
                product_details = cursor.fetchone()
            elif qr_code['product_type'] == 'new_extinguisher':
                cursor.execute('''
                    SELECT * FROM new_extinguishers 
                    WHERE qr_code_id = %s
                ''', (qr_id,))
                product_details = cursor.fetchone()
            elif qr_code['product_type'] == 'dcp_sachet':
                cursor.execute('''
                    SELECT * FROM dcp_sachets 
                    WHERE qr_code_id = %s
                ''', (qr_id,))
                product_details = cursor.fetchone()
            
            # Get service history
            cursor.execute('''
                SELECT service_type, description, amount, customer_name, customer_phone, created_at
                FROM services 
                WHERE qr_code_id = %s
                ORDER BY created_at DESC
            ''', (qr_id,))
            service_history = cursor.fetchall()
            
            return jsonify({
                'success': True,
                'qrCode': qr_code,
                'productDetails': product_details,
                'serviceHistory': service_history
            }), 200
            
        except Exception as e:
            from utils import logger
            logger.error(f"Error verifying QR code: {e}")
            return jsonify({
                'success': False,
                'message': f'Error verifying QR code: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        from utils import logger
        logger.error(f"Error in verify_qr: {e}")
        return jsonify({
            'success': False,
            'message': f'Error verifying QR code: {str(e)}'
        }), 500

@shared_bp.route('/vendors', methods=['GET'])
def vendor_locator():
    try:
        state = request.args.get('state')
        lga = request.args.get('lga')
        
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor(dictionary=True)
        
        try:
            query = '''
                SELECT id, contact_name, email, phone, business_address, state, local_government, category
                FROM vendors 
                WHERE status = "approved"
            '''
            params = []
            
            if state:
                query += ' AND state = %s'
                params.append(state)
                
            if lga:
                query += ' AND local_government = %s'
                params.append(lga)
            
            query += ' ORDER BY contact_name'
            
            cursor.execute(query, params)
            vendors = cursor.fetchall()
            
            return jsonify({
                'success': True,
                'vendors': vendors
            }), 200
            
        except Exception as e:
            from utils import logger
            logger.error(f"Error fetching vendors: {e}")
            return jsonify({
                'success': False,
                'message': f'Error fetching vendors: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        from utils import logger
        logger.error(f"Error in vendor_locator: {e}")
        return jsonify({
            'success': False,
            'message': f'Error fetching vendors: {str(e)}'
        }), 500

@shared_bp.route('/training-materials', methods=['GET'])
def get_training_materials():
    try:
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor(dictionary=True)
        
        try:
            cursor.execute('SELECT id, title, description, url FROM training_materials ORDER BY created_at DESC')
            materials = cursor.fetchall()
            
            return jsonify({
                'success': True,
                'materials': materials
            }), 200
            
        except Exception as e:
            from utils import logger
            logger.error(f"Error fetching training materials: {e}")
            return jsonify({
                'success': False,
                'message': f'Error fetching training materials: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        from utils import logger
        logger.error(f"Error in get_training_materials: {e}")
        return jsonify({
            'success': False,
            'message': f'Error fetching training materials: {str(e)}'
        }), 500