#!/usr/bin/env python3
"""Test basic socket accept under Wine"""
import socket
import sys

print("Starting test server...")
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(('127.0.0.1', 5555))
server.listen(5)
print(f"Listening on 127.0.0.1:5555")

# Try non-blocking
server.setblocking(False)

import time
for i in range(30):
    try:
        client, addr = server.accept()
        print(f"Got connection from {addr}!")
        data = client.recv(100)
        print(f"Received: {data}")
        client.close()
        break
    except BlockingIOError:
        print(f"Waiting... {i}")
        time.sleep(1)
    except Exception as e:
        print(f"Error: {e}")
        time.sleep(1)

print("Done")
