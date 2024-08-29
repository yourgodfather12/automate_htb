import re
from flask import Flask, render_template, request, jsonify, abort
from flask_socketio import SocketIO, emit
import subprocess
import os
import json

app = Flask(__name__)
socketio = SocketIO(app, async_mode='eventlet')

def is_valid_ip(ip):
    pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    return bool(pattern.match(ip))

def is_valid_domain(domain):
    pattern = re.compile(
        r'^(?:[a-zA-Z0-9]'  # First character of the domain
        r'(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)'  # Sub domain + hostname
        r'+[a-zA-Z]{2,6}\.?$'  # First level TLD
    )
    return bool(pattern.match(domain))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/start_scan', methods=['POST'])
def start_scan():
    target = request.form.get('target')
    if not target:
        abort(400, description="Target is required")

    if not (is_valid_ip(target) or is_valid_domain(target)):
        abort(400, description="Invalid IP address or domain name")

    log_level = request.form.get('log_level', 'DEBUG')

    # Start the scan in a background thread
    socketio.start_background_task(target=run_scan, target_ip=target, log_level=log_level)

    return jsonify({"status": "started"})

def run_scan(target_ip, log_level):
    command = ['python', 'main.py', target_ip, '-l', log_level, '-c', 'config.yaml']
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    try:
        for line in iter(process.stdout.readline, ''):
            socketio.emit('scan_update', {'message': line.strip()})

        process.stdout.close()
        process.wait()

        if process.returncode == 0:
            socketio.emit('scan_complete', {'status': 'completed', 'target': target_ip})
        else:
            socketio.emit('scan_complete', {'status': 'failed', 'target': target_ip})
    finally:
        process.stdout.close()
        process.stderr.close()

@app.route('/results/<string:target_ip>', methods=['GET'])
def results(target_ip):
    results_path = f'results/{target_ip}_results.json'
    if os.path.exists(results_path):
        with open(results_path, 'r') as f:
            data = json.load(f)
        return jsonify(data)
    else:
        return jsonify({"error": "Results not found"}), 404

if __name__ == '__main__':
    socketio.run(app, debug=True)
