import socket
import time

SERVER_IP = "127.0.0.1"  # Change to server IP if running on different machines
PORT = 12345
FILE_NAME = "testfile.txt"
TRANSFER_RATE = 40  # Bytes per second

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Apply options to disable Nagle and Delayed ACK
client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 0)  
client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_QUICKACK, 0)  

client_socket.connect((SERVER_IP, PORT))
print(f"Connected to {SERVER_IP}:{PORT}")

with open(FILE_NAME, "rb") as f:
    while chunk := f.read(40):  # Send 40 bytes at a time
        client_socket.sendall(chunk)
        time.sleep(1)  # Simulate 40 bytes/second transfer

client_socket.close()
print("File sent successfully.")

