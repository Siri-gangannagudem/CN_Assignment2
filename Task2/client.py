import socket

HOST = '10.0.2.15'  # Use your Linux VM IP
PORT = 5000

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    client.connect((HOST, PORT))
    print("Connected successfully!")
    data = client.recv(1024)
    print("Received:", data.decode())
except Exception as e:
    print(f"Connection failed: {e}")
finally:
    client.close()

