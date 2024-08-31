import os
import subprocess
from flask import Flask, request, jsonify, send_from_directory
from flask_socketio import SocketIO, emit
from flask_cors import CORS

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")
CORS(app)

@app.route('/api/start_scan', methods=['POST'])
def start_scan():
    data = request.json
    domain = data.get('domain')
    scan_type = data.get('scan_type')
    
    # Define the output directory based on the domain
    output_dir = f"recon_{domain}"
    
    # Launch the appropriate scan based on the scan_type
    if scan_type == "full_recon":
        command = f"./piga_hacks.sh run_full_recon {domain}"
    elif scan_type == "subdomain_enum":
        command = f"./piga_hacks.sh run_subdomain_enum {domain}"
    # Add more scan types as needed
    
    # Run the command
    subprocess.run(command, shell=True, check=True)

    return jsonify({"status": "success", "message": f"Scan started for {domain}"})


@app.route('/api/get_scan_results', methods=['GET'])
def get_scan_results():
    domain = request.args.get('domain')
    scan_type = request.args.get('scan_type')
    
    output_dir = f"recon_{domain}"
    result_file = ""

    if scan_type == "subdomain_enum":
        result_file = f"{output_dir}/subdomains/all_subdomains.txt"
    elif scan_type == "dns_enum":
        result_file = f"{output_dir}/dns/dns_enum.txt"
    # Add more result files based on the scan type

    if os.path.exists(result_file):
        with open(result_file, 'r') as f:
            result = f.read()
        return jsonify({"status": "success", "result": result})
    else:
        return jsonify({"status": "error", "message": "Results not found"})

@app.route('/results/<path:filename>', methods=['GET'])
def download_file(filename):
    return send_from_directory(directory="results", filename=filename)

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000)
