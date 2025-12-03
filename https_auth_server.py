#!/usr/bin/env python3
"""
HTTPS Auth Server for Yahoo Messenger 9 (YMSG v16)

Handles the web-based token authentication that YM 9 requires.
Must run on port 443 with SSL.
"""

import http.server
import ssl
import urllib.parse
import logging
import os

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/home/doug/yahoo-discord-bridge/https_auth.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

PORT = 443
CERT_FILE = '/home/doug/yahoo-discord-bridge/certs/server.pem'


class YahooAuthHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        logger.info(f"HTTPS Request: {args[0]}")

    def do_GET(self):
        logger.info(f"=== HTTPS GET ===")
        logger.info(f"Path: {self.path}")
        logger.info(f"Headers: {dict(self.headers)}")

        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)

        logger.info(f"Parsed path: {parsed.path}")
        logger.info(f"Query params: {query}")

        if parsed.path == '/config/pwtoken_get':
            self.handle_pwtoken_get(query)
        elif parsed.path == '/config/pwtoken_login':
            self.handle_pwtoken_login(query)
        else:
            # Unknown path - log and return 404
            logger.warning(f"Unknown path: {parsed.path}")
            self.send_response(404)
            self.end_headers()

    def handle_pwtoken_get(self, query):
        """
        Handle pwtoken_get request.

        YM 9 sends: login=USERNAME&passwd=PASSWORD&chal=CHALLENGE
        We return: 0\r\nymsgr=TOKEN\r\n

        Error codes:
        - 0 = success
        - 1212 = wrong password
        - 1235 = username doesn't exist
        - 100 = missing field
        """
        username = query.get('login', [''])[0]
        password = query.get('passwd', [''])[0]
        challenge = query.get('chal', [''])[0]

        logger.info(f"pwtoken_get: user={username} passwd={password} chal={challenge[:20]}...")

        # Accept any username/password for now
        # Generate a token that looks like a real Yahoo token (base64-ish format)
        import base64
        import hashlib
        token_data = f"{username}:{challenge}:{password}"
        token_hash = hashlib.md5(token_data.encode()).hexdigest()
        # Make it look like a real Yahoo token - they were typically longer base64 strings
        token = base64.b64encode(f"{username}|{token_hash}|{challenge[:16]}".encode()).decode()

        # Response format: status code on first line, then key=value pairs
        # Use \r\n for Windows compatibility
        response = f"0\r\nymsgr={token}\r\n"

        logger.info(f"Returning token for {username}: {token[:40]}...")
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.send_header('Content-Length', str(len(response)))
        self.end_headers()
        self.wfile.write(response.encode())

    def handle_pwtoken_login(self, query):
        """
        Handle pwtoken_login request.

        YM 9 sends: token=TOKEN
        We return:
        0\r\n
        crumb=CRUMB\r\n
        Y=Y_COOKIE\r\n
        T=T_COOKIE\r\n
        cookievalidfor=86400\r\n
        """
        token = query.get('token', [''])[0]

        logger.info(f"pwtoken_login: token={token[:40]}...")

        # Generate fake cookies that look realistic
        # These will be sent back in the YMSG AUTHRESP packet
        import base64
        import hashlib

        # Extract username from token if possible
        try:
            decoded = base64.b64decode(token).decode()
            username = decoded.split('|')[0]
        except:
            username = "user"

        # Generate realistic-looking cookies
        crumb = hashlib.md5(token.encode()).hexdigest()[:16]
        y_cookie = f"v=1&n={username}&l={username}/o/1&p=ymsgr&r=fg&intl=us"
        t_cookie = f"z={hashlib.md5((token+'T').encode()).hexdigest()}&a=QAE&sk={hashlib.md5((token+'SK').encode()).hexdigest()[:24]}&d=c2k9"

        # Use \r\n line endings for Windows
        response = f"0\r\ncrumb={crumb}\r\nY={y_cookie}\r\nT={t_cookie}\r\ncookievalidfor=86400\r\n"

        logger.info(f"Returning cookies for {username}: crumb={crumb}")
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.send_header('Content-Length', str(len(response)))
        self.end_headers()
        self.wfile.write(response.encode())


def generate_self_signed_cert():
    """Generate a self-signed certificate if none exists"""
    cert_dir = os.path.dirname(CERT_FILE)
    if not os.path.exists(cert_dir):
        os.makedirs(cert_dir)

    if not os.path.exists(CERT_FILE):
        logger.info("Generating self-signed certificate...")
        import subprocess
        # Generate self-signed cert valid for login.yahoo.com
        subprocess.run([
            'openssl', 'req', '-x509', '-newkey', 'rsa:2048',
            '-keyout', CERT_FILE, '-out', CERT_FILE,
            '-days', '365', '-nodes',
            '-subj', '/CN=login.yahoo.com'
        ], check=True)
        logger.info(f"Certificate generated: {CERT_FILE}")
    return CERT_FILE


def run_server():
    cert_file = generate_self_signed_cert()

    server_address = ('0.0.0.0', PORT)
    httpd = http.server.HTTPServer(server_address, YahooAuthHandler)

    # Wrap with SSL
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_file)
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

    logger.info(f"HTTPS Auth Server listening on 0.0.0.0:{PORT}")
    logger.info("Waiting for Yahoo Messenger 9 auth requests...")
    httpd.serve_forever()


if __name__ == '__main__':
    run_server()
