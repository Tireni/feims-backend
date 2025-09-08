# officers.py
from flask import Blueprint, jsonify, request
import mysql.connector
import uuid
from datetime import datetime

from utils import get_db_connection

officers_bp = Blueprint('officers', __name__)

# ===================== OFFICER APIs =====================
@officers_bp.route('', methods=['POST'])
def officer_register():
    try:
        data = request.get_json()
        
        required_fields = ['name', 'phone', 'serviceNumber']
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
            # Check if officer already exists
            cursor.execute('SELECT id FROM officers WHERE service_number = %s', (data['serviceNumber'],))
            if cursor.fetchone():
                return jsonify({
                    'success': False,
                    'message': 'Officer with this service number already exists'
                }), 409
            
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
                'officer': {
                    'id': officer_id,
                    'name': data['name'],
                    'serviceNumber': data['serviceNumber']
                }
            }), 201
            
        except Exception as e:
            conn.rollback()
            from utils import logger
            logger.error(f"Error registering officer: {e}")
            return jsonify({
                'success': False,
                'message': f'Error registering officer: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        from utils import logger
        logger.error(f"Error in officer_register: {e}")
        return jsonify({
            'success': False,
            'message': f'Error registering officer: {str(e)}'
        }), 500

@officers_bp.route('/login', methods=['POST'])
def officer_login():
    try:
        data = request.get_json()
        
        if not data or not data.get('serviceNumber'):
            return jsonify({
                'success': False,
                'message': 'Service number is required'
            }), 400
        
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor(dictionary=True)
        
        try:
            cursor.execute('SELECT id, name, service_number FROM officers WHERE service_number = %s', (data['serviceNumber'],))
            officer = cursor.fetchone()
            
            if not officer:
                return jsonify({
                    'success': False,
                    'message': 'Officer not found'
                }), 404
            
            return jsonify({
                'success': True,
                'message': 'Officer login successful',
                'officer': officer
            }), 200
            
        except Exception as e:
            from utils import logger
            logger.error(f"Error in officer login: {e}")
            return jsonify({
                'success': False,
                'message': f'Error logging in: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        from utils import logger
        logger.error(f"Error in officer_login: {e}")
        return jsonify({
            'success': False,
            'message': f'Error logging in: {str(e)}'
        }), 500