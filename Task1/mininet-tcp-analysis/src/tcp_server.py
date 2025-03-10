from socket import socket, AF_INET, SOCK_STREAM
import subprocess
import sys

def start_tcp_server(host='0.0.0.0', port=5001):
    server_socket = socket(AF_INET, SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"TCP server listening on {host}:{port}")

    while True:
        client_socket, addr = server_socket.accept()
        print(f"Connection from {addr} has been established!")
        handle_client(client_socket)

def handle_client(client_socket):
    while True:
        data = client_socket.recv(1024)
        if not data:
            break
        print(f"Received data: {data.decode()}")
        client_socket.sendall(data)  # Echo back the received data

    client_socket.close()

def start_iperf_server(port=5201):
    """Start iperf3 server"""
    cmd = f"iperf3 -s -p {port}"
    
    try:
        process = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE)
        print(f"Server started on port {port}")
        return process
    except Exception as e:
        print(f"Error starting server: {e}")
        sys.exit(1)

if __name__ == "__main__":
    server_process = start_iperf_server()
    try:
        server_process.wait()
    except KeyboardInterrupt:
        server_process.terminate()
        print("\nServer stopped")