# shared.py
from flask import Blueprint, jsonify, request
import mysql.connector
import uuid
import logging
from utils import get_db_connection

shared_bp = Blueprint('shared', __name__)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ===================== SHARED APIs =====================
@shared_bp.route('/scan/<qr_id>', methods=['GET'])
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