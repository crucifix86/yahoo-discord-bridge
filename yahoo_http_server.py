#!/usr/bin/env python3
"""
Yahoo HTTP/HTTPS Server for YM9 Authentication

Handles:
- GET /capacity (port 80) - Returns pager server address
- GET /config/pwtoken_get (port 443) - Returns auth token
- GET /config/pwtoken_login (port 443) - Returns session cookies

This allows Yahoo Messenger 9+ to authenticate through the bridge.
"""

import http.server
import ssl
import socketserver
import threading
import logging
import os
import urllib.parse

logger = logging.getLogger(__name__)

# Directory for SSL certificates
CERT_DIR = os.path.dirname(os.path.abspath(__file__))


class YahooHTTPHandler(http.server.BaseHTTPRequestHandler):
    """Handle Yahoo Messenger HTTP requests"""

    def log_message(self, format, *args):
        logger.info(f"HTTP: {self.path} - {args[0] if args else ''}")

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        logger.info(f"HTTP Request: {path} query={query}")

        if path == '/capacity' or path.endswith('/capacity'):
            self.handle_capacity()
        elif '/pwtoken_get' in path:
            self.handle_pwtoken_get(query)
        elif '/pwtoken_login' in path:
            self.handle_pwtoken_login(query)
        else:
            # Default response for other requests
            self.handle_capacity()

    def handle_capacity(self):
        """
        Handle capacity request - tells YM9 where to connect

        Response format:
        COLO_CAPACITY=1
        CS_IP_ADDRESS=127.0.0.1
        CS_PORT=5050
        """
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()

        response = "COLO_CAPACITY=1\nCS_IP_ADDRESS=127.0.0.1\nCS_PORT=5050\n"
        self.wfile.write(response.encode('utf-8'))
        logger.info("Served capacity request -> 127.0.0.1:5050")

    def handle_pwtoken_get(self, query):
        """
        Handle token request - YM9 sends credentials here

        Request: /config/pwtoken_get?src=ymsgr&login=USER&passwd=PASS&chal=CHALLENGE

        Response format (success):
        0
        ymsgr=TOKEN_STRING
        partnerid=VALUE

        Response format (error):
        ERROR_CODE
        """
        login = query.get('login', [''])[0]
        # We accept any credentials since we're bridging to Discord

        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()

        # Return a fake token - we'll accept anything on the YMSG side
        token = f"DISCORD_BRIDGE_TOKEN_{login}"
        response = f"0\nymsgr={token}\npartnerid=discord\n"
        self.wfile.write(response.encode('utf-8'))
        logger.info(f"Served pwtoken_get for user: {login}")

    def handle_pwtoken_login(self, query):
        """
        Handle token login - exchanges token for cookies

        Request: /config/pwtoken_login?src=ymsgr&token=TOKEN

        Response format (success):
        0
        crumb=CRUMB_VALUE
        Y=COOKIE_VALUE
        T=COOKIE_VALUE
        """
        token = query.get('token', [''])[0]

        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        # Set cookies via headers as Yahoo expects
        self.send_header("Set-Cookie", "Y=discord_y_cookie; path=/; domain=.yahoo.com")
        self.send_header("Set-Cookie", "T=discord_t_cookie; path=/; domain=.yahoo.com")
        self.send_header("Set-Cookie", "B=discord_b_cookie; path=/; domain=.yahoo.com")
        self.end_headers()

        # Return crumb and cookie values in body too
        response = "0\ncrumb=discord_crumb\nY=discord_y_cookie\nT=discord_t_cookie\n"
        self.wfile.write(response.encode('utf-8'))
        logger.info(f"Served pwtoken_login for token: {token[:20]}...")


class YahooHTTPServer:
    """
    Combined HTTP (port 80) and HTTPS (port 443) server
    """

    def __init__(self, http_port=80, https_port=443):
        self.http_port = http_port
        self.https_port = https_port
        self.http_server = None
        self.https_server = None
        self.http_thread = None
        self.https_thread = None
        self.running = False

    def generate_self_signed_cert(self):
        """Generate a self-signed certificate for HTTPS"""
        cert_file = os.path.join(CERT_DIR, 'yahoo_cert.pem')
        key_file = os.path.join(CERT_DIR, 'yahoo_key.pem')

        if os.path.exists(cert_file) and os.path.exists(key_file):
            logger.info("Using existing SSL certificates")
            return cert_file, key_file

        logger.info("Generating self-signed SSL certificate...")

        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.primitives import serialization
            import datetime

            # Generate key
            key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )

            # Generate certificate
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Sunnyvale"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Yahoo Inc"),
                x509.NameAttribute(NameOID.COMMON_NAME, "login.yahoo.com"),
            ])

            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=365)
            ).add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName("login.yahoo.com"),
                    x509.DNSName("localhost"),
                    x509.DNSName("*.yahoo.com"),
                ]),
                critical=False,
            ).sign(key, hashes.SHA256())

            # Write key
            with open(key_file, "wb") as f:
                f.write(key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))

            # Write cert
            with open(cert_file, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))

            logger.info(f"Generated SSL certificate: {cert_file}")
            return cert_file, key_file

        except ImportError:
            logger.warning("cryptography not installed, using openssl command")
            # Fall back to openssl command
            import subprocess
            subprocess.run([
                'openssl', 'req', '-x509', '-newkey', 'rsa:2048',
                '-keyout', key_file, '-out', cert_file,
                '-days', '365', '-nodes',
                '-subj', '/CN=login.yahoo.com/O=Yahoo Inc/C=US'
            ], check=True, capture_output=True)
            return cert_file, key_file

    def start(self):
        """Start both HTTP and HTTPS servers"""
        self.running = True

        # Start HTTP server on port 80
        try:
            self.http_server = socketserver.TCPServer(
                ("127.0.0.1", self.http_port),
                YahooHTTPHandler
            )
            self.http_server.socket.setsockopt(
                __import__('socket').SOL_SOCKET,
                __import__('socket').SO_REUSEADDR, 1
            )
            self.http_thread = threading.Thread(
                target=self.http_server.serve_forever,
                daemon=True
            )
            self.http_thread.start()
            logger.info(f"HTTP server listening on 127.0.0.1:{self.http_port}")
        except PermissionError:
            logger.warning(f"Cannot bind to port {self.http_port} (needs root)")
        except Exception as e:
            logger.error(f"Failed to start HTTP server: {e}")

        # Start HTTPS server on port 443
        try:
            cert_file, key_file = self.generate_self_signed_cert()

            self.https_server = socketserver.TCPServer(
                ("127.0.0.1", self.https_port),
                YahooHTTPHandler
            )
            self.https_server.socket.setsockopt(
                __import__('socket').SOL_SOCKET,
                __import__('socket').SO_REUSEADDR, 1
            )

            # Wrap with SSL
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert_file, key_file)
            # Allow older TLS versions for compatibility with YM9
            context.minimum_version = ssl.TLSVersion.TLSv1

            self.https_server.socket = context.wrap_socket(
                self.https_server.socket,
                server_side=True
            )

            self.https_thread = threading.Thread(
                target=self.https_server.serve_forever,
                daemon=True
            )
            self.https_thread.start()
            logger.info(f"HTTPS server listening on 127.0.0.1:{self.https_port}")
        except PermissionError:
            logger.warning(f"Cannot bind to port {self.https_port} (needs root)")
        except Exception as e:
            logger.error(f"Failed to start HTTPS server: {e}")

    def stop(self):
        """Stop both servers"""
        self.running = False
        if self.http_server:
            self.http_server.shutdown()
        if self.https_server:
            self.https_server.shutdown()
        logger.info("Yahoo HTTP/HTTPS servers stopped")


def main():
    """Run the Yahoo HTTP/HTTPS server standalone"""
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

    print("Yahoo HTTP/HTTPS Server for YM9 Authentication")
    print("=" * 50)
    print("This server handles:")
    print("  - GET /capacity (port 80) - Pager server address")
    print("  - GET /config/pwtoken_get (port 443) - Auth token")
    print("  - GET /config/pwtoken_login (port 443) - Session cookies")
    print()
    print("Note: Ports 80 and 443 require root/admin privileges")
    print()

    server = YahooHTTPServer()
    server.start()

    print("Press Ctrl+C to stop...")
    try:
        import time
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping...")
        server.stop()


if __name__ == "__main__":
    main()
