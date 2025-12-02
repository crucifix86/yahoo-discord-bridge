#!/usr/bin/env python3
"""Simple HTTP server to serve Yahoo server list"""

import http.server
import socketserver

class YahooServerHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        # Return server list in Yahoo format with port
        response = b"COLO_CAPACITY=1\nCS_IP_ADDRESS=127.0.0.1\nCS_PORT=5050\n"
        self.wfile.write(response)
        print(f"Served request: {self.path}")

    def log_message(self, format, *args):
        print(f"HTTP: {args[0]}")

if __name__ == "__main__":
    PORT = 80
    with socketserver.TCPServer(("127.0.0.1", PORT), YahooServerHandler) as httpd:
        print(f"HTTP server listening on 127.0.0.1:{PORT}")
        httpd.serve_forever()
