from flask import Flask, request, jsonify

# ==========================================
# EDR SERVER CONFIGURATION
# ==========================================
# '0.0.0.0' allows the server to listen on all available network interfaces.
# Users do NOT need to change the HOST IP. Just ensure the PORT is available.
SERVER_HOST = '0.0.0.0'
SERVER_PORT = 5000

# Centralized list of banned processes (Must be lowercase)
BANNED_PROCESSES = ["notepad.exe", "calculatorapp.exe"]
# ==========================================

app = Flask(__name__)

@app.route('/api/telemetry', methods=['POST'])
def receive_telemetry():
    data = request.json
    machine = data.get('machine_name')
    process = data.get('process_name')
    pid = data.get('pid', 'Unknown')
    action = data.get('action', 'Monitor Only')
    
    # Extracting the network connections list from the payload
    network_ips = data.get('network_connections', [])

    print(f"🚨 [ALERT] Endpoint: {machine} | Process: {process} (PID: {pid}) | Action: {action}")
    
    # If the process is establishing external connections, print the target IPs
    if network_ips:
        print(f"   🌐 [NETWORK ACTIVITY] External Connections: {', '.join(network_ips)}")
        
    return {"status": "ok"}, 200

@app.route('/api/rules', methods=['GET'])
def get_rules():
    return jsonify(BANNED_PROCESSES), 200

if __name__ == '__main__':
    print(f"🛡️ EDR Server is Listening on port {SERVER_PORT}!")
    print("Waiting for telemetry and network logs...")
    app.run(host=SERVER_HOST, port=SERVER_PORT)