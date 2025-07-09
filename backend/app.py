
from flask import Flask, jsonify
from flask_cors import CORS
import psutil
import json
import os
from datetime import datetime

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Store for anomaly detection
traffic_baseline = None
last_traffic_stats = None

@app.route('/api/cpu-memory')
def get_cpu_memory():
    """Get CPU and memory usage"""
    try:
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        
        return jsonify({
            'cpu_percent': cpu_percent,
            'memory_percent': memory.percent,
            'memory_used': memory.used,
            'memory_total': memory.total,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/processes')
def get_processes():
    """Get running processes with suspicious activity detection"""
    try:
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'cpu_percent', 'memory_percent', 'create_time']):
            try:
                info = proc.info
                # Simple suspicious activity detection
                suspicious = (
                    info['cpu_percent'] and info['cpu_percent'] > 80 or
                    info['memory_percent'] and info['memory_percent'] > 50 or
                    any(keyword in (info['name'] or '').lower() for keyword in ['miner', 'crypto', 'hack'])
                )
                
                processes.append({
                    'pid': info['pid'],
                    'name': info['name'] or 'Unknown',
                    'cmdline': ' '.join(info['cmdline']) if info['cmdline'] else '',
                    'cpu_percent': info['cpu_percent'] or 0,
                    'memory_percent': info['memory_percent'] or 0,
                    'create_time': datetime.fromtimestamp(info['create_time']).isoformat() if info['create_time'] else '',
                    'suspicious': suspicious
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        return jsonify(processes)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/network-connections')
def get_network_connections():
    """Get network connections with suspicious port detection"""
    try:
        connections = []
        suspicious_ports = [1337, 4444, 5555, 6666, 7777, 8080, 9999]
        
        for conn in psutil.net_connections():
            if conn.status == 'ESTABLISHED':
                local_port = conn.laddr.port if conn.laddr else 0
                remote_port = conn.raddr.port if conn.raddr else 0
                
                suspicious = (
                    local_port in suspicious_ports or 
                    remote_port in suspicious_ports or
                    local_port > 60000 or remote_port > 60000
                )
                
                connections.append({
                    'pid': conn.pid or 0,
                    'laddr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A",
                    'raddr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A",
                    'status': conn.status,
                    'suspicious': suspicious
                })
        
        return jsonify(connections)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/traffic-stats')
def get_traffic_stats():
    """Get network traffic statistics with anomaly detection"""
    global traffic_baseline, last_traffic_stats
    
    try:
        # Get current network stats
        net_io = psutil.net_io_counters()
        current_stats = {
            'bytes_sent': net_io.bytes_sent,
            'bytes_recv': net_io.bytes_recv,
            'timestamp': datetime.now().isoformat()
        }
        
        # Calculate bytes per second if we have previous data
        sent_bytes_per_sec = 0
        recv_bytes_per_sec = 0
        
        if last_traffic_stats:
            time_diff = 1  # Assume 1 second for simplicity
            sent_bytes_per_sec = max(0, (current_stats['bytes_sent'] - last_traffic_stats['bytes_sent']) / time_diff)
            recv_bytes_per_sec = max(0, (current_stats['bytes_recv'] - last_traffic_stats['bytes_recv']) / time_diff)
        
        # Simple anomaly detection (threshold: 1MB/s)
        anomaly_threshold = 1000000  # 1MB/s
        anomaly = sent_bytes_per_sec > anomaly_threshold or recv_bytes_per_sec > anomaly_threshold
        
        last_traffic_stats = current_stats
        
        return jsonify({
            'sent_bytes_per_sec': sent_bytes_per_sec,
            'recv_bytes_per_sec': recv_bytes_per_sec,
            'total_sent': current_stats['bytes_sent'],
            'total_recv': current_stats['bytes_recv'],
            'anomaly': anomaly,
            'timestamp': current_stats['timestamp']
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/full-scan')
def full_scan():
    """Perform a comprehensive system scan"""
    try:
        # Get all data
        cpu_data = get_cpu_memory().get_json()
        process_data = get_processes().get_json()
        network_data = get_network_connections().get_json()
        traffic_data = get_traffic_stats().get_json()
        
        scan_result = {
            'scan_time': datetime.now().isoformat(),
            'cpu_memory': cpu_data,
            'processes': process_data,
            'network': network_data,
            'traffic': traffic_data,
            'summary': {
                'total_processes': len(process_data) if isinstance(process_data, list) else 0,
                'suspicious_processes': len([p for p in process_data if p.get('suspicious', False)]) if isinstance(process_data, list) else 0,
                'active_connections': len(network_data) if isinstance(network_data, list) else 0,
                'suspicious_connections': len([c for c in network_data if c.get('suspicious', False)]) if isinstance(network_data, list) else 0,
                'traffic_anomaly': traffic_data.get('anomaly', False) if isinstance(traffic_data, dict) else False
            }
        }
        
        return jsonify({
            'status': 'completed',
            'message': 'Full system scan completed successfully',
            'results': scan_result
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/save-scan')
def save_scan():
    """Save current system state to JSON file"""
    try:
        # Get current scan data
        scan_data = full_scan().get_json()
        
        # Save to file
        filename = 'last_scan.json'
        with open(filename, 'w') as f:
            json.dump(scan_data, f, indent=2)
        
        return jsonify({
            'status': 'saved',
            'message': f'System state saved to {filename}',
            'filename': filename,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print("Starting System Monitor Flask Backend...")
    print("Available endpoints:")
    print("- http://localhost:5000/api/cpu-memory")
    print("- http://localhost:5000/api/processes")
    print("- http://localhost:5000/api/network-connections")
    print("- http://localhost:5000/api/traffic-stats")
    print("- http://localhost:5000/api/full-scan")
    print("- http://localhost:5000/api/save-scan")
    app.run(debug=True, host='0.0.0.0', port=5000)
