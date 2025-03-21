from flask import Flask, jsonify, request
from pymongo import MongoClient
from datetime import datetime, timedelta
from functools import wraps
import os
from typing import Dict, List, Optional

app = Flask(__name__)

# MongoDB connection
class Database:
    def __init__(self):
        self.client = MongoClient('mongodb://localhost:27017/')
        self.db = self.client['CTI']
        self.threats = self.db['threats']

# Initialize database
db = Database()

# Authentication decorator
def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if api_key and api_key == os.getenv('API_KEY', 'your-secret-key'):
            return f(*args, **kwargs)
        return jsonify({"error": "Invalid API key"}), 401
    return decorated_function

@app.route('/api/v1/threats', methods=['GET'])
@require_api_key
def get_threats():
    """Fetch all threat intelligence reports"""
    try:
        # Parse query parameters
        source = request.args.get('source')
        days = int(request.args.get('days', 7))
        limit = int(request.args.get('limit', 100))
        
        # Build query
        query = {}
        if source:
            query['source'] = source
            
        # Add date filter
        start_date = datetime.now() - timedelta(days=days)
        query['timestamp'] = {'$gte': start_date}
        
        # Execute query
        threats = list(db.threats.find(
            query,
            {'_id': 0}  # Exclude MongoDB ID
        ).limit(limit))
        
        return jsonify({
            'status': 'success',
            'count': len(threats),
            'data': threats
        })
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/v1/alerts', methods=['GET'])
@require_api_key
def get_alerts():
    """Fetch real-time security alerts"""
    try:
        # Parse query parameters
        severity = request.args.get('severity')
        hours = int(request.args.get('hours', 24))
        limit = int(request.args.get('limit', 100))
        
        # Build query
        query = {
            'type': {'$in': ['ids_alert', 'network_monitor']}
        }
        
        if severity:
            query['data.severity'] = severity.upper()
            
        # Add time filter
        start_time = datetime.now() - timedelta(hours=hours)
        query['timestamp'] = {'$gte': start_time}
        
        # Execute query
        alerts = list(db.threats.find(
            query,
            {'_id': 0}
        ).limit(limit).sort('timestamp', -1))
        
        return jsonify({
            'status': 'success',
            'count': len(alerts),
            'data': alerts
        })
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/v1/stats', methods=['GET'])
@require_api_key
def get_stats():
    """Get threat statistics"""
    try:
        # Get total counts
        total_threats = db.threats.count_documents({'type': 'threat_intel'})
        total_alerts = db.threats.count_documents({
            'type': {'$in': ['ids_alert', 'network_monitor']}
        })
        
        # Get severity distribution
        severity_pipeline = [
            {'$match': {'data.severity': {'$exists': True}}},
            {'$group': {
                '_id': '$data.severity',
                'count': {'$sum': 1}
            }}
        ]
        
        severity_stats = list(db.threats.aggregate(severity_pipeline))
        
        return jsonify({
            'status': 'success',
            'data': {
                'total_threats': total_threats,
                'total_alerts': total_alerts,
                'severity_distribution': severity_stats
            }
        })
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Resource not found'}), 404

@app.errorhandler(500)
def server_error(e):
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)