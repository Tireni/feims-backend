import json
from flask import Blueprint, jsonify, request, current_app
import mysql.connector
from collections import defaultdict
from datetime import datetime, timedelta 
import psutil
import time
import os
from utils import logger

from utils import admin_token_required, get_db_connection

admin_bp = Blueprint('admin', __name__)

# ===================== ADMIN APIs =====================
@admin_bp.route('/login', methods=['POST'])
def admin_login():
    try:
        from utils import ADMIN_USERNAME, ADMIN_PASSWORD
        import jwt
        
        data = request.get_json()
        
        if not data or not data.get('username') or not data.get('password'):
            return jsonify({
                'success': False,
                'message': 'Username and password are required'
            }), 400
        
        if data['username'] != ADMIN_USERNAME or data['password'] != ADMIN_PASSWORD:
            return jsonify({
                'success': False,
                'message': 'Invalid admin credentials'
            }), 401
        
        token = jwt.encode({
            'username': data['username'],
            'role': 'admin',
            'exp': datetime.now() + timedelta(hours=24)
        }, current_app.config['SECRET_KEY'], algorithm="HS256")
        
        return jsonify({
            'success': True,
            'message': 'Admin login successful',
            'token': token
        }), 200
        
    except Exception as e:
        from utils import logger
        logger.error(f"Error in admin login: {e}")
        return jsonify({
            'success': False,
            'message': f'Error: {str(e)}'
        }), 500

@admin_bp.route('/generate-qr', methods=['POST'])
@admin_token_required
def admin_generate_qr_code(current_admin):
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'success': False, 'message': 'No data provided'}), 400
        
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
        
        try:
            import qrcode
            import io
            import base64
            import uuid
            
            generated_codes = []
            
            for i in range(quantity):
                qr_id = str(uuid.uuid4())
                
                # Create URL for scanning
                qr_url = f"https://nfdrc.ng/feims/scan.php/{qr_id}"
                
                qr = qrcode.QRCode(
                    version=1,
                    error_correction=qrcode.constants.ERROR_CORRECT_L,
                    box_size=10,
                    border=4,
                )
                qr.add_data(qr_url)
                qr.make(fit=True)
                
                img = qr.make_image(fill_color="#ff7b00", back_color="white")
                
                buffered = io.BytesIO()
                img.save(buffered, format="PNG")
                img_bytes = buffered.getvalue()
                img_str = base64.b64encode(img_bytes).decode('utf-8')
                print(f"Generated QR image length: {len(img_str)}") 
                
                # Insert QR code with admin as vendor_id (or NULL if you prefer)
                cursor.execute('''
                    INSERT INTO qr_codes (id, vendor_id, product_type, size, type, qr_image, status)
                    VALUES (%s, %s, %s, %s, %s, %s, 'inactive')
                ''', (
                    qr_id,
                    'admin',  # Using 'admin' as vendor_id for admin-generated codes
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
                    'qrImage': f"data:image/png;base64,{img_str}",
                    'url': qr_url
                })
            
            conn.commit()
            
            return jsonify({
                'success': True,
                'message': f'Successfully generated {quantity} QR codes',
                'codes': generated_codes
            }), 201
            
        except Exception as e:
            conn.rollback()
            logger.error(f"Error generating QR codes: {e}")
            return jsonify({
                'success': False,
                'message': f'Error generating QR codes: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        logger.error(f"Error in admin_generate_qr_code: {e}")
        return jsonify({
            'success': False,
            'message': f'Error generating QR codes: {str(e)}'
        }), 500

@admin_bp.route('/real-time-metrics', methods=['GET'])
@admin_token_required
def admin_real_time_metrics(current_admin):
    try:
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor(dictionary=True)
        
        try:
            # Get basic counts with error handling for each query
            vendors_count = 0
            qr_codes_count = 0
            mobile_entries_count = 0
            vendor_entries_count = 0
            training_bookings_count = 0
            
            try:
                cursor.execute('SELECT COUNT(*) as count FROM vendors')
                vendors_count = cursor.fetchone()['count']
            except Exception as e:
                logger.warning(f"Error counting vendors: {e}")
                
            try:
                cursor.execute('SELECT COUNT(*) as count FROM qr_codes')
                qr_codes_count = cursor.fetchone()['count']
            except Exception as e:
                logger.warning(f"Error counting QR codes: {e}")
                
            try:
                cursor.execute('SELECT COUNT(*) as count FROM mobile_entries')
                mobile_entries_count = cursor.fetchone()['count']
            except Exception as e:
                logger.warning(f"Error counting mobile entries: {e}")
                
            try:
                cursor.execute('SELECT COUNT(*) as count FROM vendor_entries')
                vendor_entries_count = cursor.fetchone()['count']
            except Exception as e:
                logger.warning(f"Error counting vendor entries: {e}")
                
            try:
                cursor.execute('SELECT COUNT(*) as count FROM training_bookings')
                training_bookings_count = cursor.fetchone()['count']
            except Exception as e:
                logger.warning(f"Error counting training bookings: {e}")
            
            # Get recent activities with error handling
            recent_activities = []
            try:
                cursor.execute('''
                    (SELECT 'vendor_registration' as type, contact_name as name, created_at 
                     FROM vendors ORDER BY created_at DESC LIMIT 5)
                    UNION ALL
                    (SELECT 'qr_generated' as type, product_type as name, created_at 
                     FROM qr_codes ORDER BY created_at DESC LIMIT 5)
                    UNION ALL
                    (SELECT 'sale_recorded' as type, customer_name as name, created_at 
                     FROM sales ORDER BY created_at DESC LIMIT 5)
                    UNION ALL
                    (SELECT 'training_booking' as type, name, created_at 
                     FROM training_bookings ORDER BY created_at DESC LIMIT 5)
                    ORDER BY created_at DESC LIMIT 10
                ''')
                recent_activities = cursor.fetchall()
            except Exception as e:
                logger.warning(f"Error fetching recent activities: {e}")
            
            # Get system performance metrics
            db_connections = 0
            try:
                cursor.execute('SHOW STATUS WHERE `variable_name` = "Threads_connected"')
                db_result = cursor.fetchone()
                if db_result:
                    db_connections = db_result['Value']
            except Exception as e:
                logger.warning(f"Error getting DB connections: {e}")
                
            # System performance metrics with fallbacks
            try:
                cpu_percent = psutil.cpu_percent(interval=1)
                memory_info = psutil.virtual_memory()
                memory_percent = memory_info.percent
                disk_usage = psutil.disk_usage('/').percent
                
                # Process metrics (Flask app)
                process = psutil.Process(os.getpid())
                memory_usage_mb = process.memory_info().rss / 1024 / 1024  # Convert to MB
            except Exception as e:
                logger.warning(f"Error getting system metrics: {e}")
                cpu_percent = 0
                memory_percent = 0
                disk_usage = 0
                memory_usage_mb = 0
            
            return jsonify({
                'success': True,
                'metrics': {
                    'vendors': vendors_count,
                    'qr_codes': qr_codes_count,
                    'mobile_entries': mobile_entries_count,
                    'vendor_entries': vendor_entries_count,
                    'training_bookings': training_bookings_count
                },
                'performance': {
                    'response_time': 0,
                    'memory_usage': memory_percent,
                    'cpu_usage': cpu_percent,
                    'disk_usage': disk_usage,
                    'memory_usage_mb': round(memory_usage_mb, 2),
                    'active_connections': int(db_connections)
                },
                'recent_activities': recent_activities
            }), 200
            
        except Exception as e:
            logger.error(f"Error fetching real-time metrics: {e}")
            return jsonify({
                'success': False,
                'message': f'Error fetching metrics: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        logger.error(f"Error in admin_real_time_metrics: {e}")
        return jsonify({
            'success': False,
            'message': f'Error fetching metrics: {str(e)}'
        }), 500

@admin_bp.route('/dashboard', methods=['GET'])
@admin_token_required
def admin_dashboard(current_admin):
    try:
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor(dictionary=True)
        
        try:
            # Get vendor counts by status
            cursor.execute('SELECT status, COUNT(*) as count FROM vendors GROUP BY status')
            vendor_counts = {row['status']: row['count'] for row in cursor.fetchall()}
            
            # Get total QR codes by status
            cursor.execute('SELECT status, COUNT(*) as count FROM qr_codes GROUP BY status')
            qr_counts = {row['status']: row['count'] for row in cursor.fetchall()}
            
            # Get recent activities
            cursor.execute('''
                (SELECT 'vendor_registration' as type, contact_name as name, created_at 
                 FROM vendors ORDER BY created_at DESC LIMIT 5)
                UNION ALL
                (SELECT 'qr_generated' as type, product_type as name, created_at 
                 FROM qr_codes ORDER BY created_at DESC LIMIT 5)
                UNION ALL
                (SELECT 'sale_recorded' as type, customer_name as name, created_at 
                 FROM sales ORDER BY created_at DESC LIMIT 5)
                ORDER BY created_at DESC LIMIT 10
            ''')
            recent_activities = cursor.fetchall()
            
            return jsonify({
                'success': True,
                'stats': {
                    'vendors': {
                        'total': sum(vendor_counts.values()),
                        'approved': vendor_counts.get('approved', 0),
                        'pending': vendor_counts.get('pending', 0),
                        'rejected': vendor_counts.get('rejected', 0)
                    },
                    'qrCodes': {
                        'total': sum(qr_counts.values()),
                        'active': qr_counts.get('active', 0),
                        'inactive': qr_counts.get('inactive', 0),
                        'pending': qr_counts.get('pending', 0)
                    }
                },
                'recentActivities': recent_activities
            }), 200
            
        except Exception as e:
            from utils import logger
            logger.error(f"Error fetching dashboard data: {e}")
            return jsonify({
                'success': False,
                'message': f'Error fetching dashboard data: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        from utils import logger
        logger.error(f"Error in admin_dashboard: {e}")
        return jsonify({
            'success': False,
            'message': f'Error fetching dashboard data: {str(e)}'
        }), 500

@admin_bp.route('/vendors', methods=['GET'])
@admin_token_required
def admin_get_vendors(current_admin):
    try:
        status = request.args.get('status')
        
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor(dictionary=True)
        
        try:
            if status and status in ['pending', 'approved', 'rejected']:
                cursor.execute('''
                    SELECT id, contact_name, email, phone, business_address, state, 
                           local_government, category, status, created_at
                    FROM vendors 
                    WHERE status = %s
                    ORDER BY created_at DESC
                ''', (status,))
            else:
                cursor.execute('''
                    SELECT id, contact_name, email, phone, business_address, state, 
                           local_government, category, status, created_at
                    FROM vendors 
                    ORDER BY created_at DESC
                ''')
            
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
        logger.error(f"Error in admin_get_vendors: {e}")
        return jsonify({
            'success': False,
            'message': f'Error fetching vendors: {str(e)}'
        }), 500

@admin_bp.route('/vendors/<vendor_id>/approve', methods=['POST'])
@admin_token_required
def admin_approve_vendor(current_admin, vendor_id):
    try:
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor()
        
        try:
            cursor.execute('UPDATE vendors SET status = "approved" WHERE id = %s', (vendor_id,))
            
            if cursor.rowcount == 0:
                return jsonify({
                    'success': False,
                    'message': 'Vendor not found'
                }), 404
            
            conn.commit()
            
            return jsonify({
                'success': True,
                'message': 'Vendor approved successfully'
            }), 200
            
        except Exception as e:
            conn.rollback()
            from utils import logger
            logger.error(f"Error approving vendor: {e}")
            return jsonify({
                'success': False,
                'message': f'Error approving vendor: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        from utils import logger
        logger.error(f"Error in admin_approve_vendor: {e}")
        return jsonify({
            'success': False,
            'message': f'Error approving vendor: {str(e)}'
        }), 500

@admin_bp.route('/vendors/<vendor_id>/reject', methods=['POST'])
@admin_token_required
def admin_reject_vendor(current_admin, vendor_id):
    try:
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor()
        
        try:
            cursor.execute('UPDATE vendors SET status = "rejected" WHERE id = %s', (vendor_id,))
            
            if cursor.rowcount == 0:
                return jsonify({
                    'success': False,
                    'message': 'Vendor not found'
                }), 404
            
            conn.commit()
            
            return jsonify({
                'success': True,
                'message': 'Vendor rejected successfully'
            }), 200
            
        except Exception as e:
            conn.rollback()
            from utils import logger
            logger.error(f"Error rejecting vendor: {e}")
            return jsonify({
                'success': False,
                'message': f'Error rejecting vendor: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        from utils import logger
        logger.error(f"Error in admin_reject_vendor: {e}")
        return jsonify({
            'success': False,
            'message': f'Error rejecting vendor: {str(e)}'
        }), 500

@admin_bp.route('/qr-codes', methods=['GET'])
@admin_token_required
def admin_get_qr_codes(current_admin):
    try:
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor(dictionary=True)
        
        try:
            cursor.execute('''
                SELECT q.id, q.qr_image, q.vendor_id, q.product_type, q.size, q.type, q.status, q.created_at, q.activated_at,
                       COALESCE(v.contact_name, mv.full_name) as vendor_name,
                       COALESCE(v.email, mv.username) as vendor_contact
                FROM qr_codes q
                LEFT JOIN vendors v ON q.vendor_id = v.id
                LEFT JOIN mobile_vendors mv ON q.vendor_id = mv.id
                ORDER BY q.created_at DESC
            ''')
            qr_codes = cursor.fetchall()
            
            return jsonify({
                'success': True,
                'qrCodes': qr_codes
            }), 200
            
        except Exception as e:
            logger.error(f"Error fetching QR codes: {e}")
            return jsonify({
                'success': False,
                'message': f'Error fetching QR codes: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        logger.error(f"Error in admin_get_qr_codes: {e}")
        return jsonify({
            'success': False,
            'message': f'Error fetching QR codes: {str(e)}'
        }), 500

@admin_bp.route('/qr-codes/<qr_id>/update-status', methods=['POST'])
@admin_token_required
def admin_update_qr_status(current_admin, qr_id):
    try:
        data = request.get_json()
        
        if not data or 'status' not in data or data['status'] not in ['active', 'inactive']:
            return jsonify({
                'success': False,
                'message': 'Valid status (active/inactive) is required'
            }), 400
        
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor()
        
        try:
            if data['status'] == 'active':
                cursor.execute('UPDATE qr_codes SET status = %s, activated_at = NOW() WHERE id = %s', 
                              (data['status'], qr_id))
            else:
                cursor.execute('UPDATE qr_codes SET status = %s WHERE id = %s', 
                              (data['status'], qr_id))
            
            if cursor.rowcount == 0:
                return jsonify({
                    'success': False,
                    'message': 'QR code not found'
                }), 404
            
            conn.commit()
            
            return jsonify({
                'success': True,
                'message': f'QR code status updated to {data["status"]}'
            }), 200
            
        except Exception as e:
            conn.rollback()
            from utils import logger
            logger.error(f"Error updating QR code status: {e}")
            return jsonify({
                'success': False,
                'message': f'Error updating QR code status: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        from utils import logger
        logger.error(f"Error in admin_update_qr_status: {e}")
        return jsonify({
            'success': False,
            'message': f'Error updating QR code status: {str(e)}'
        }), 500

@admin_bp.route('/analytics', methods=['GET'])
@admin_token_required
def admin_analytics(current_admin):
    try:
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor(dictionary=True)
        
        try:
            # Get vendor registrations by month
            cursor.execute('''
                SELECT DATE_FORMAT(created_at, '%Y-%m') as month, COUNT(*) as count
                FROM vendors 
                WHERE created_at >= DATE_SUB(NOW(), INTERVAL 6 MONTH)
                GROUP BY month 
                ORDER BY month
            ''')
            vendor_registrations = cursor.fetchall()
            
            # Get QR code generations by month
            cursor.execute('''
                SELECT DATE_FORMAT(created_at, '%Y-%m') as month, COUNT(*) as count
                FROM qr_codes 
                WHERE created_at >= DATE_SUB(NOW(), INTERVAL 6 MONTH)
                GROUP BY month 
                ORDER BY month
            ''')
            qr_generations = cursor.fetchall()
            
            # Get sales by product type
            cursor.execute('''
                SELECT product_type, COUNT(*) as count, SUM(amount) as revenue
                FROM sales 
                GROUP BY product_type
            ''')
            sales_by_product = cursor.fetchall()
            
            return jsonify({
                'success': True,
                'analytics': {
                    'vendorRegistrations': vendor_registrations,
                    'qrGenerations': qr_generations,
                    'salesByProduct': sales_by_product
                }
            }), 200
            
        except Exception as e:
            from utils import logger
            logger.error(f"Error fetching analytics: {e}")
            return jsonify({
                'success': False,
                'message': f'Error fetching analytics: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        from utils import logger
        logger.error(f"Error in admin_analytics: {e}")
        return jsonify({
            'success': False,
            'message': f'Error fetching analytics: {str(e)}'
        }), 500

@admin_bp.route('/mobile-vendors', methods=['GET'])
@admin_token_required
def admin_get_mobile_vendors(current_admin):
    try:
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor(dictionary=True)
        
        try:
            cursor.execute('''
                SELECT id, full_name, username, created_at
                FROM mobile_vendors 
                ORDER BY created_at DESC
            ''')
            mobile_vendors = cursor.fetchall()
            
            return jsonify({
                'success': True,
                'mobileVendors': mobile_vendors
            }), 200
            
        except Exception as e:
            from utils import logger
            logger.error(f"Error fetching mobile vendors: {e}")
            return jsonify({
                'success': False,
                'message': f'Error fetching mobile vendors: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        from utils import logger
        logger.error(f"Error in admin_get_mobile_vendors: {e}")
        return jsonify({
            'success': False,
            'message': f'Error fetching mobile vendors: {str(e)}'
        }), 500

@admin_bp.route('/mobile-entries', methods=['GET'])
@admin_token_required
def admin_get_mobile_entries(current_admin):
    try:
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor(dictionary=True)
        
        try:
            # Get optional query parameters for filtering
            page = int(request.args.get('page', 1))
            limit = int(request.args.get('limit', 50))
            product_type = request.args.get('product_type')
            date_from = request.args.get('date_from')
            date_to = request.args.get('date_to')
            
            offset = (page - 1) * limit
            
            # Build the base query
            query = '''
                SELECT id, product_type, data, created_at
                FROM mobile_entries 
                WHERE 1=1
            '''
            params = []
            
            # Add filters if provided
            if product_type and product_type in ['existing_extinguisher', 'new_extinguisher', 'dcp_sachet']:
                query += ' AND product_type = %s'
                params.append(product_type)
                
            if date_from:
                query += ' AND DATE(created_at) >= %s'
                params.append(date_from)
                
            if date_to:
                query += ' AND DATE(created_at) <= %s'
                params.append(date_to)
            
            # Add ordering and pagination
            query += ' ORDER BY created_at DESC LIMIT %s OFFSET %s'
            params.extend([limit, offset])
            
            cursor.execute(query, params)
            mobile_entries = cursor.fetchall()
            
            # Get total count for pagination
            count_query = 'SELECT COUNT(*) as total FROM mobile_entries WHERE 1=1'
            count_params = []
            
            if product_type and product_type in ['existing_extinguisher', 'new_extinguisher', 'dcp_sachet']:
                count_query += ' AND product_type = %s'
                count_params.append(product_type)
                
            if date_from:
                count_query += ' AND DATE(created_at) >= %s'
                count_params.append(date_from)
                
            if date_to:
                count_query += ' AND DATE(created_at) <= %s'
                count_params.append(date_to)
            
            cursor.execute(count_query, count_params)
            total_count = cursor.fetchone()['total']
            
            # Parse JSON data if it's stored as string
            for entry in mobile_entries:
                if isinstance(entry['data'], str):
                    try:
                        entry['data'] = json.loads(entry['data'])
                    except json.JSONDecodeError:
                        entry['data'] = {}
            
            return jsonify({
                'success': True,
                'mobileEntries': mobile_entries,
                'pagination': {
                    'page': page,
                    'limit': limit,
                    'total': total_count,
                    'pages': (total_count + limit - 1) // limit
                }
            }), 200
            
        except Exception as e:
            logger.error(f"Error fetching mobile entries: {e}")
            return jsonify({
                'success': False,
                'message': f'Error fetching mobile entries: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        logger.error(f"Error in admin_get_mobile_entries: {e}")
        return jsonify({
            'success': False,
            'message': f'Error fetching mobile entries: {str(e)}'
        }), 500

@admin_bp.route('/vendor-entries', methods=['GET'])
@admin_token_required
def admin_get_vendor_entries(current_admin):
    try:
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor(dictionary=True)
        
        try:
            # Get optional query parameters for filtering
            page = int(request.args.get('page', 1))
            limit = int(request.args.get('limit', 50))
            product_type = request.args.get('product_type')
            vendor_id = request.args.get('vendor_id')
            date_from = request.args.get('date_from')
            date_to = request.args.get('date_to')
            
            offset = (page - 1) * limit
            
            # Build the base query
            query = '''
                SELECT ve.*, 
                       COALESCE(v.contact_name, mv.full_name) as vendor_name,
                       COALESCE(v.email, mv.username) as vendor_contact
                FROM vendor_entries ve
                LEFT JOIN vendors v ON ve.vendor_id = v.id
                LEFT JOIN mobile_vendors mv ON ve.vendor_id = mv.id
                WHERE 1=1
            '''
            params = []
            
            # Add filters if provided
            if product_type and product_type in ['existing_extinguisher', 'new_extinguisher', 'dcp_sachet']:
                query += ' AND ve.product_type = %s'
                params.append(product_type)
                
            if vendor_id:
                query += ' AND ve.vendor_id = %s'
                params.append(vendor_id)
                
            if date_from:
                query += ' AND DATE(ve.created_at) >= %s'
                params.append(date_from)
                
            if date_to:
                query += ' AND DATE(ve.created_at) <= %s'
                params.append(date_to)
            
            # Add ordering and pagination
            query += ' ORDER BY ve.created_at DESC LIMIT %s OFFSET %s'
            params.extend([limit, offset])
            
            cursor.execute(query, params)
            vendor_entries = cursor.fetchall()
            
            # Get total count for pagination
            count_query = '''
                SELECT COUNT(*) as total 
                FROM vendor_entries ve
                WHERE 1=1
            '''
            count_params = []
            
            if product_type and product_type in ['existing_extinguisher', 'new_extinguisher', 'dcp_sachet']:
                count_query += ' AND ve.product_type = %s'
                count_params.append(product_type)
                
            if vendor_id:
                count_query += ' AND ve.vendor_id = %s'
                count_params.append(vendor_id)
                
            if date_from:
                count_query += ' AND DATE(ve.created_at) >= %s'
                count_params.append(date_from)
                
            if date_to:
                count_query += ' AND DATE(ve.created_at) <= %s'
                count_params.append(date_to)
            
            cursor.execute(count_query, count_params)
            total_count = cursor.fetchone()['total']
            
            # Parse JSON data if it's stored as string
            for entry in vendor_entries:
                if isinstance(entry['data'], str):
                    try:
                        entry['data'] = json.loads(entry['data'])
                    except json.JSONDecodeError:
                        entry['data'] = {}
            
            return jsonify({
                'success': True,
                'vendorEntries': vendor_entries,
                'pagination': {
                    'page': page,
                    'limit': limit,
                    'total': total_count,
                    'pages': (total_count + limit - 1) // limit
                }
            }), 200
            
        except Exception as e:
            logger.error(f"Error fetching vendor entries: {e}")
            return jsonify({
                'success': False,
                'message': f'Error fetching vendor entries: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        logger.error(f"Error in admin_get_vendor_entries: {e}")
        return jsonify({
            'success': False,
            'message': f'Error fetching vendor entries: {str(e)}'
        }), 500
    
@admin_bp.route('/extinguisher-data', methods=['GET'])
@admin_token_required
def admin_extinguisher_data(current_admin):
    try:
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor(dictionary=True)
        
        try:
            # Get existing extinguishers
            cursor.execute('''
                SELECT ee.*, qr.product_type, qr.size, qr.type, qr.status as qr_status,
                       COALESCE(v.contact_name, mv.full_name) as vendor_name
                FROM existing_extinguishers ee
                JOIN qr_codes qr ON ee.qr_code_id = qr.id
                LEFT JOIN vendors v ON qr.vendor_id = v.id
                LEFT JOIN mobile_vendors mv ON qr.vendor_id = mv.id
                ORDER BY ee.created_at DESC
            ''')
            existing_extinguishers = cursor.fetchall()
            
            # Get new extinguishers
            cursor.execute('''
                SELECT ne.*, qr.product_type, qr.size, qr.type, qr.status as qr_status,
                       COALESCE(v.contact_name, mv.full_name) as vendor_name
                FROM new_extinguishers ne
                JOIN qr_codes qr ON ne.qr_code_id = qr.id
                LEFT JOIN vendors v ON qr.vendor_id = v.id
                LEFT JOIN mobile_vendors mv ON qr.vendor_id = mv.id
                ORDER BY ne.created_at DESC
            ''')
            new_extinguishers = cursor.fetchall()
            
            # Get DCP sachets
            cursor.execute('''
                SELECT ds.*, qr.product_type, qr.size, qr.type, qr.status as qr_status,
                       COALESCE(v.contact_name, mv.full_name) as vendor_name
                FROM dcp_sachets ds
                JOIN qr_codes qr ON ds.qr_code_id = qr.id
                LEFT JOIN vendors v ON qr.vendor_id = v.id
                LEFT JOIN mobile_vendors mv ON qr.vendor_id = mv.id
                ORDER BY ds.created_at DESC
            ''')
            dcp_sachets = cursor.fetchall()
            
            return jsonify({
                'success': True,
                'extinguisherData': {
                    'existingExtinguishers': existing_extinguishers,
                    'newExtinguishers': new_extinguishers,
                    'dcpSachets': dcp_sachets
                }
            }), 200
            
        except Exception as e:
            from utils import logger
            logger.error(f"Error fetching extinguisher data: {e}")
            return jsonify({
                'success': False,
                'message': f'Error fetching extinguisher data: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        from utils import logger
        logger.error(f"Error in admin_extinguisher_data: {e}")
        return jsonify({
            'success': False,
            'message': f'Error fetching extinguisher data: {str(e)}'
        }), 500

@admin_bp.route('/sales', methods=['GET'])
@admin_token_required
def admin_get_sales(current_admin):
    try:
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor(dictionary=True)
        
        try:
            cursor.execute('''
                SELECT s.*, COALESCE(v.contact_name, mv.full_name) as vendor_name
                FROM sales s
                LEFT JOIN vendors v ON s.vendor_id = v.id
                LEFT JOIN mobile_vendors mv ON s.vendor_id = mv.id
                ORDER BY s.created_at DESC
            ''')
            sales = cursor.fetchall()
            
            return jsonify({
                'success': True,
                'sales': sales
            }), 200
            
        except Exception as e:
            from utils import logger
            logger.error(f"Error fetching sales: {e}")
            return jsonify({
                'success': False,
                'message': f'Error fetching sales: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        from utils import logger
        logger.error(f"Error in admin_get_sales: {e}")
        return jsonify({
            'success': False,
            'message': f'Error fetching sales: {str(e)}'
        }), 500
    
@admin_bp.route('/training-bookings', methods=['GET'])
@admin_token_required
def admin_get_training_bookings(current_admin):
    try:
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor(dictionary=True)
        
        try:
            cursor.execute('''
                SELECT id, name, phone, plate_or_address, booking_date, booking_time, created_at
                FROM training_bookings 
                ORDER BY created_at DESC
            ''')
            training_bookings = cursor.fetchall()
            
            return jsonify({
                'success': True,
                'trainingBookings': training_bookings
            }), 200
            
        except Exception as e:
            from utils import logger
            logger.error(f"Error fetching training bookings: {e}")
            return jsonify({
                'success': False,
                'message': f'Error fetching training bookings: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        from utils import logger
        logger.error(f"Error in admin_get_training_bookings: {e}")
        return jsonify({
            'success': False,
            'message': f'Error fetching training bookings: {str(e)}'
        }), 500
    
@admin_bp.route('/training-analytics', methods=['GET'])
@admin_token_required
def admin_training_analytics(current_admin):
    try:
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor(dictionary=True)
        
        try:
            # Get training bookings by month
            cursor.execute('''
                SELECT DATE_FORMAT(created_at, '%Y-%m') as month, COUNT(*) as count
                FROM training_bookings 
                WHERE created_at >= DATE_SUB(NOW(), INTERVAL 6 MONTH)
                GROUP BY month 
                ORDER BY month
            ''')
            monthly_data = cursor.fetchall()
            
            return jsonify({
                'success': True,
                'monthly': monthly_data
            }), 200
            
        except Exception as e:
            from utils import logger
            logger.error(f"Error fetching training analytics: {e}")
            return jsonify({
                'success': False,
                'message': f'Error fetching training analytics: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        from utils import logger
        logger.error(f"Error in admin_training_analytics: {e}")
        return jsonify({
            'success': False,
            'message': f'Error fetching training analytics: {str(e)}'
        }), 500

@admin_bp.route('/officers', methods=['GET'])
@admin_token_required
def admin_get_officers(current_admin):
    try:
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor(dictionary=True)
        
        try:
            cursor.execute('''
                SELECT id, name, phone, service_number, created_at
                FROM officers 
                ORDER BY created_at DESC
            ''')
            officers = cursor.fetchall()
            
            return jsonify({
                'success': True,
                'officers': officers
            }), 200
            
        except Exception as e:
            from utils import logger
            logger.error(f"Error fetching officers: {e}")
            return jsonify({
                'success': False,
                'message': f'Error fetching officers: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        from utils import logger
        logger.error(f"Error in admin_get_officers: {e}")
        return jsonify({
            'success': False,
            'message': f'Error fetching officers: {str(e)}'
        }), 500
    

@admin_bp.route('/sales-analytics', methods=['GET'])
@admin_token_required
def admin_sales_analytics(current_admin):
    try:
        conn = get_db_connection()
        if conn is None:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        cursor = conn.cursor(dictionary=True)
        
        try:
            # Get sales by product type
            cursor.execute('''
                SELECT product_type, COUNT(*) as count, SUM(amount) as revenue
                FROM sales 
                GROUP BY product_type
            ''')
            sales_by_product = cursor.fetchall()
            
            # Get sales by payment method
            cursor.execute('''
                SELECT payment_method, COUNT(*) as count, SUM(amount) as revenue
                FROM sales 
                GROUP BY payment_method
            ''')
            sales_by_payment = cursor.fetchall()
            
            # Get sales by month
            cursor.execute('''
                SELECT DATE_FORMAT(created_at, '%Y-%m') as month, 
                       COUNT(*) as count, 
                       SUM(amount) as revenue
                FROM sales 
                WHERE created_at >= DATE_SUB(NOW(), INTERVAL 6 MONTH)
                GROUP BY month 
                ORDER BY month
            ''')
            sales_by_month = cursor.fetchall()
            
            # Get total sales statistics
            cursor.execute('''
                SELECT COUNT(*) as total_sales, 
                       SUM(amount) as total_revenue,
                       AVG(amount) as avg_sale_value
                FROM sales
            ''')
            total_stats = cursor.fetchone()
            
            return jsonify({
                'success': True,
                'analytics': {
                    'byProduct': sales_by_product,
                    'byPayment': sales_by_payment,
                    'byMonth': sales_by_month,
                    'totalStats': total_stats
                }
            }), 200
            
        except Exception as e:
            from utils import logger
            logger.error(f"Error fetching sales analytics: {e}")
            return jsonify({
                'success': False,
                'message': f'Error fetching sales analytics: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        from utils import logger
        logger.error(f"Error in admin_sales_analytics: {e}")
        return jsonify({
            'success': False,
            'message': f'Error fetching sales analytics: {str(e)}'
        }), 500