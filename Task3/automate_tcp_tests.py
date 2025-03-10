import socket
import time
import subprocess
import os

# Constants
SERVER_IP = "127.0.0.1"
PORT = 12345
FILE_SIZE = 4096  # 4 KB file
FILE_NAME = "testfile.txt"
CAPTURE_FILE = "capture.pcap"
TRANSFER_RATE = 40  # Bytes per second

# Configuration combinations
CONFIGS = [
    ("Nagle ON", "Delayed-ACK ON", True, True),
    ("Nagle ON", "Delayed-ACK OFF", True, False),
    ("Nagle OFF", "Delayed-ACK ON", False, True),
    ("Nagle OFF", "Delayed-ACK OFF", False, False),
]

def start_tcpdump():
    """ Starts packet capture using tcpdump with sudo """
    print("[INFO] Starting packet capture...")
    return subprocess.Popen(["sudo", "tcpdump", "-i", "any", "-w", CAPTURE_FILE], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def stop_tcpdump(capture_process):
    """ Stops packet capture using sudo kill """
    print("[INFO] Stopping packet capture...")
    subprocess.run(["sudo", "kill", str(capture_process.pid)])

def run_server(nagle, delayed_ack):
    """ Starts the TCP server with specified configurations """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    if not nagle:
        server_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    
    server_socket.bind(("0.0.0.0", PORT))
    server_socket.listen(1)
    
    print(f"[SERVER] Listening on port {PORT}...")
    conn, addr = server_socket.accept()
    print(f"[SERVER] Connected by {addr}")

    with open("received_file.txt", "wb") as f:
        while True:
            data = conn.recv(40)
            if not data:
                break
            f.write(data)

    conn.close()
    server_socket.close()
    print("[SERVER] File received successfully.")

def run_client(nagle, delayed_ack):
    """ Starts the TCP client with specified configurations """
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    if not nagle:
        client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    
    if not delayed_ack:
        client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_QUICKACK, 1)

    client_socket.connect((SERVER_IP, PORT))
    print(f"[CLIENT] Connected to {SERVER_IP}:{PORT}")

    with open(FILE_NAME, "rb") as f:
        while chunk := f.read(40):
            client_socket.sendall(chunk)
            time.sleep(1)  # Simulating 40 bytes/sec transfer

    client_socket.close()
    print("[CLIENT] File sent successfully.")

def analyze_capture():
    """ Analyze the captured traffic using tshark """
    metrics = {}

    # Total packets captured
    metrics["Total Packets"] = subprocess.getoutput(f"tshark -r {CAPTURE_FILE} | wc -l")

    # Throughput: Total bytes transferred / time taken
    total_bytes = int(subprocess.getoutput(f"tshark -r {CAPTURE_FILE} -T fields -e frame.len | awk '{{sum += $1}} END {{print sum}}'"))
    total_time = float(subprocess.getoutput(f"tshark -r {CAPTURE_FILE} -T fields -e frame.time_relative | tail -1"))
    metrics["Throughput (bytes/sec)"] = total_bytes / total_time if total_time > 0 else 0

    # Goodput: Only useful data (4 KB file size) / time taken
    metrics["Goodput (bytes/sec)"] = FILE_SIZE / total_time if total_time > 0 else 0

    # Packet Loss Rate
    retransmissions = int(subprocess.getoutput(f"tshark -r {CAPTURE_FILE} -Y 'tcp.analysis.retransmission' | wc -l"))
    total_tcp_packets = int(subprocess.getoutput(f"tshark -r {CAPTURE_FILE} -Y 'tcp' | wc -l"))
    metrics["Packet Loss Rate (%)"] = (retransmissions / total_tcp_packets * 100) if total_tcp_packets > 0 else 0

    # Maximum Packet Size
    max_packet_size = int(subprocess.getoutput(f"tshark -r {CAPTURE_FILE} -T fields -e frame.len | sort -nr | head -1"))
    metrics["Max Packet Size (bytes)"] = max_packet_size

    return metrics

def run_test(config):
    """ Runs a full test for one configuration """
    nagle_state, delayed_ack_state, nagle, delayed_ack = config
    print(f"\n--- Running Configuration: {nagle_state}, {delayed_ack_state} ---")

    # Start packet capture
    capture_process = start_tcpdump()
    time.sleep(1)  # Wait to ensure capture starts

    # Start server
    server_process = subprocess.Popen(["python3", "-c", f"import automate_tcp_tests; automate_tcp_tests.run_server({nagle}, {delayed_ack})"])
    time.sleep(1)  # Give server time to start

    # Start client
    run_client(nagle, delayed_ack)

    # Stop packet capture
    stop_tcpdump(capture_process)

    # Kill server process
    server_process.terminate()
    server_process.wait()

    # Analyze results
    metrics = analyze_capture()

    # Print and save results
    print(f"Results for {nagle_state}, {delayed_ack_state}:")
    for key, value in metrics.items():
        print(f"  {key}: {value}")

    with open(f"results_{nagle_state}_{delayed_ack_state}.txt", "w") as f:
        for key, value in metrics.items():
            f.write(f"{key}: {value}\n")

if __name__ == "__main__":
    for config in CONFIGS:
        run_test(config)
    print("\n✅ All tests completed!")

