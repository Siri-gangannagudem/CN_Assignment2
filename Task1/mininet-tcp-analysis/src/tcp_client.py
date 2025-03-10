import socket
import time
import json
import subprocess
import sys

def load_config(config_file):
    with open(config_file, 'r') as f:
        return json.load(f)

def tcp_client(server_ip, server_port, message):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((server_ip, server_port))
        s.sendall(message.encode())
        response = s.recv(1024)
        print('Received', repr(response.decode()))

def start_iperf_client(server_ip, port=5201, duration=150, congestion='reno', bandwidth='10M'):
    """Start iperf3 client with specified parameters"""
    cmd = f"iperf3 -c {server_ip} -p {port} -b {bandwidth} -P 10 -t {duration} -C {congestion}"
    
    try:
        process = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE)
        return process
    except Exception as e:
        print(f"Error starting client: {e}")
        sys.exit(1)

def run_staggered_test(server_ip, congestion_scheme):
    """Run staggered test with multiple clients"""
    # Start H1 at T=0s for 150s
    h1 = start_iperf_client(server_ip, congestion=congestion_scheme)
    
    # Start H3 at T=15s for 120s
    time.sleep(15)
    h3 = start_iperf_client(server_ip, duration=120, congestion=congestion_scheme)
    
    # Start H4 at T=30s for 90s
    time.sleep(15)
    h4 = start_iperf_client(server_ip, duration=90, congestion=congestion_scheme)
    
    return h1, h3, h4

if __name__ == "__main__":
    config = load_config('../config.json')
    server_ip = config['server_ip']
    server_port = config['server_port']
    message = "Hello from TCP client!"

    for i in range(1, 7):
        print(f"Starting TCP client H{i}...")
        tcp_client(server_ip, server_port, message)
        time.sleep(1)  # Delay between clients