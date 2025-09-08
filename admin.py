# admin.py
from flask import Blueprint, jsonify, request
import mysql.connector
from collections import defaultdict
from datetime import datetime

from utils import admin_token_required, get_db_connection

admin_bp = Blueprint('admin', __name__)

# ===================== ADMIN APIs =====================
@admin_bp.route('/login', methods=['POST'])
def admin_login():
    try:
        from utils import ADMIN_USERNAME, ADMIN_PASSWORD
        from main import app
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
        }, app.config['SECRET_KEY'], algorithm="HS256")
        
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
                SELECT q.id, q.product_type, q.size, q.type, q.status, q.created_at, q.activated_at,
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
            cursor.execute('''
                SELECT id, product_type, data, created_at
                FROM mobile_entries 
                ORDER BY created_at DESC
            ''')
            mobile_entries = cursor.fetchall()
            
            return jsonify({
                'success': True,
                'mobileEntries': mobile_entries
            }), 200
            
        except Exception as e:
            from utils import logger
            logger.error(f"Error fetching mobile entries: {e}")
            return jsonify({
                'success': False,
                'message': f'Error fetching mobile entries: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        from utils import logger
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
            cursor.execute('''
                SELECT ve.*, COALESCE(v.contact_name, mv.full_name) as vendor_name
                FROM vendor_entries ve
                LEFT JOIN vendors v ON ve.vendor_id = v.id
                LEFT JOIN mobile_vendors mv ON ve.vendor_id = mv.id
                ORDER BY ve.created_at DESC
            ''')
            vendor_entries = cursor.fetchall()
            
            return jsonify({
                'success': True,
                'vendorEntries': vendor_entries
            }), 200
            
        except Exception as e:
            from utils import logger
            logger.error(f"Error fetching vendor entries: {e}")
            return jsonify({
                'success': False,
                'message': f'Error fetching vendor entries: {str(e)}'
            }), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        from utils import logger
        logger.error(f"Error in admin_get_vendor_entries: {e}")
        return jsonify({
            'success': False,
            'message': f'Error fetching vendor entries: {str(e)}'
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