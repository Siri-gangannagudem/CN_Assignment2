import socket

HOST = '0.0.0.0'  # Listen on all network interfaces
PORT = 12345      # Port number
FILE_SIZE = 4096  # 4 KB
FILE_NAME = "received_file.txt"

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen(1)
print(f"Server listening on {HOST}:{PORT}")

conn, addr = server_socket.accept()
print(f"Connected by {addr}")

# Apply socket options AFTER accepting connection
conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 0)  
conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_QUICKACK, 0) 

with open(FILE_NAME, "wb") as f:
    while True:
        data = conn.recv(40)  # Receive in small chunks (40 bytes per second)
        if not data:
            break
        f.write(data)

conn.close()
server_socket.close()
print("File received successfully.")

