#!/usr/bin/env python3
"""
GraphQL AuthZ Fuzzer - Dashboard Server
Real-time monitoring and control interface
"""

import sys
import os
# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import threading
import json
import time
from datetime import datetime
from collections import defaultdict

# Import the fuzzer
from graphql_authz_fuzzer import GraphQLAuthzFuzzer, FuzzResult

app = Flask(__name__)
app.config['SECRET_KEY'] = 'graphql-fuzzer-secret-key-2024'
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Global scan state
scan_state = {
    'status': 'idle',  # idle, scanning, paused, completed, error
    'progress': 0,
    'total': 0,
    'completed': 0,
    'current_mutation': '',
    'current_message': '',
    'results': [],
    'start_time': None,
    'end_time': None,
    'config': {},
    'is_running': False,
    'scan_id': None
}

class ProgressFuzzer(GraphQLAuthzFuzzer):
    """Extended fuzzer with progress reporting"""
    
    def run_with_progress(self):
        """Run fuzzer and yield progress updates"""
        fields = self.discover_mutations()
        self.results = []
        
        total = len(fields)
        yield {'type': 'init', 'total': total, 'fields': [f['name'] for f in fields]}
        
        from concurrent.futures import ThreadPoolExecutor, as_completed
        
        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            futures = {pool.submit(self.test_mutation, f): f for f in fields}
            
            completed = 0
            for future in as_completed(futures):
                result = future.result()
                self.results.append(result)
                completed += 1
                
                yield {
                    'type': 'progress',
                    'mutation': result.mutation,
                    'result': result.to_dict(),
                    'completed': completed,
                    'total': total,
                    'percentage': (completed / total) * 100
                }
        
        # Sort results
        order = {f["name"]: i for i, f in enumerate(fields)}
        self.results.sort(key=lambda r: order.get(r.mutation, 0))
        
        yield {
            'type': 'complete',
            'results': [r.to_dict() for r in self.results],
            'summary': self._generate_summary()
        }
    
    def _generate_summary(self):
        """Generate summary statistics"""
        critical = [r for r in self.results if r.severity == "Critical"]
        high = [r for r in self.results if r.severity == "High"]
        secure = [r for r in self.results if r.severity == "Secure"]
        info = [r for r in self.results if r.severity == "Info"]
        
        return {
            'total': len(self.results),
            'critical': len(critical),
            'high': len(high),
            'secure': len(secure),
            'info': len(info),
            'critical_mutations': [r.mutation for r in critical],
            'has_vulnerabilities': len(critical) > 0,
            'vulnerability_percentage': (len(critical) / len(self.results) * 100) if self.results else 0
        }

@app.route('/')
def dashboard():
    """Main dashboard page"""
    return render_template('dashboard.html')

@app.route('/api/status')
def get_status():
    """Get current scan status"""
    return jsonify({
        'status': scan_state['status'],
        'progress': scan_state['progress'],
        'total': scan_state['total'],
        'completed': scan_state['completed'],
        'current_mutation': scan_state['current_mutation'],
        'current_message': scan_state['current_message'],
        'results_count': len(scan_state['results']),
        'is_running': scan_state['is_running']
    })

@app.route('/api/results')
def get_results():
    """Get all scan results"""
    return jsonify({
        'results': scan_state['results'],
        'summary': scan_state.get('summary', {})
    })

@app.route('/api/reset')
def reset_scan():
    """Reset scan state"""
    global scan_state
    scan_state['status'] = 'idle'
    scan_state['progress'] = 0
    scan_state['total'] = 0
    scan_state['completed'] = 0
    scan_state['results'] = []
    scan_state['current_mutation'] = ''
    scan_state['is_running'] = False
    scan_state['summary'] = {}
    return jsonify({'status': 'reset'})

@socketio.on('start_scan')
def handle_start_scan(data):
    """Start a new scan from dashboard"""
    global scan_state
    
    # Don't start if already running
    if scan_state['is_running']:
        emit('scan_error', {'message': 'Scan already in progress'})
        return
    
    # Parse configuration
    config = {
        'url': data.get('url'),
        'token': data.get('token'),
        'baseline_token': data.get('baseline_token'),
        'public_mutations': [m.strip() for m in data.get('public_mutations', '').split(',') if m.strip()],
        'timeout': float(data.get('timeout', 8)),
        'retries': int(data.get('retries', 1)),
        'workers': int(data.get('workers', 4))
    }
    
    scan_state['config'] = config
    scan_state['status'] = 'scanning'
    scan_state['is_running'] = True
    scan_state['start_time'] = datetime.now().isoformat()
    scan_state['results'] = []
    scan_state['current_mutation'] = ''
    scan_state['progress'] = 0
    scan_state['completed'] = 0
    scan_state['total'] = 0
    
    emit('scan_started', {'message': 'Scan started', 'config': config})
    
    # Run scan in background thread
    def run_scan():
        global scan_state
        
        try:
            # Create fuzzer instance
            fuzzer = ProgressFuzzer(
                url=config['url'],
                restricted_token=config['token'],
                baseline_token=config.get('baseline_token'),
                timeout=config['timeout'],
                retries=config['retries'],
                workers=config['workers'],
                public_mutations=config['public_mutations']
            )
            
            # Run with progress updates
            for update in fuzzer.run_with_progress():
                if update['type'] == 'init':
                    scan_state['total'] = update['total']
                    socketio.emit('scan_init', {
                        'total': update['total'],
                        'fields': update['fields']
                    })
                
                elif update['type'] == 'progress':
                    scan_state['completed'] = update['completed']
                    scan_state['progress'] = update['percentage']
                    scan_state['current_mutation'] = update['mutation']
                    scan_state['results'].append(update['result'])
                    
                    socketio.emit('scan_progress', {
                        'mutation': update['mutation'],
                        'result': update['result'],
                        'completed': update['completed'],
                        'total': update['total'],
                        'percentage': update['percentage']
                    })
                
                elif update['type'] == 'complete':
                    scan_state['status'] = 'completed'
                    scan_state['is_running'] = False
                    scan_state['end_time'] = datetime.now().isoformat()
                    scan_state['summary'] = update['summary']
                    
                    socketio.emit('scan_complete', {
                        'results': update['results'],
                        'summary': update['summary']
                    })
        
        except Exception as e:
            scan_state['status'] = 'error'
            scan_state['is_running'] = False
            scan_state['current_message'] = str(e)
            socketio.emit('scan_error', {'message': str(e)})
    
    thread = threading.Thread(target=run_scan)
    thread.daemon = True
    thread.start()

@socketio.on('stop_scan')
def handle_stop_scan():
    """Stop the current scan"""
    global scan_state
    if scan_state['is_running']:
        scan_state['status'] = 'stopped'
        scan_state['is_running'] = False
        scan_state['current_message'] = 'Scan stopped by user'
        emit('scan_stopped', {'message': 'Scan stopped by user'})
    else:
        emit('scan_error', {'message': 'No scan in progress'})

if __name__ == '__main__':
    socketio.run(app, debug=True, port=5000, host='0.0.0.0')
