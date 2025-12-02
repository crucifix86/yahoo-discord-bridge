#!/usr/bin/env python3
"""
Standalone YMSG Server - Runs on native Linux

This handles Yahoo Messenger client connections. The Discord side
runs separately under Wine.

Supports both YM5.x (YMSG v10) and YM9+ (YMSG v16).
"""

import socket
import threading
import logging
import json
import time
import os
import sys
import hashlib

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ymsg.protocol import (
    YMSGPacket, encode_packet, decode_packet,
    YMSG_HEADER_SIZE, Service, Status
)
from mapping.smileys import yahoo_to_discord, strip_yahoo_formatting
from yahoo_http_server import YahooHTTPServer

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class YMSGSession:
    def __init__(self, session_id, sock, addr):
        self.session_id = session_id
        self.sock = sock
        self.address = addr
        self.username = None
        self.authenticated = False
        self.lock = threading.Lock()
        self.protocol_version = 16  # Default to v16, updated on first packet

    def send_packet(self, service, status=0, data=None):
        packet = YMSGPacket(
            service=service,
            status=status,
            session_id=self.session_id,
            data=data or {}
        )
        packet.version = self.protocol_version  # Match client version
        raw = encode_packet(packet)
        with self.lock:
            try:
                self.sock.sendall(raw)
                logger.debug(f"Sent to {self.username or self.address}: service={service}")
            except Exception as e:
                logger.error(f"Error sending: {e}")

    def close(self):
        try:
            self.sock.close()
        except:
            pass


class StandaloneYMSGServer:
    def __init__(self, host='127.0.0.1', port=5050):
        self.host = host
        self.port = port
        self.sessions = {}
        self.sessions_lock = threading.Lock()
        self.username_to_session = {}
        self.session_counter = 0
        self.running = False
        self.server_socket = None

        # Friend data - can be updated by external process
        self.friend_groups = {"Friends": ["discord_user1", "discord_user2"]}
        self.friend_status = {"discord_user1": 0, "discord_user2": 0}

    def start(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        self.running = True

        logger.info(f"YMSG Server listening on {self.host}:{self.port}")

        accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
        accept_thread.start()

        return accept_thread

    def _accept_loop(self):
        logger.info("Accept loop started")
        while self.running:
            try:
                client_sock, addr = self.server_socket.accept()
                logger.info(f"New connection from {addr}")

                self.session_counter += 1
                session_id = self.session_counter

                session = YMSGSession(session_id, client_sock, addr)
                with self.sessions_lock:
                    self.sessions[session_id] = session

                client_thread = threading.Thread(
                    target=self._handle_client,
                    args=(session,),
                    daemon=True
                )
                client_thread.start()

            except Exception as e:
                if self.running:
                    logger.error(f"Accept error: {e}")

    def _handle_client(self, session):
        logger.info(f"Handling client {session.address}")
        try:
            while self.running:
                # Read header
                header = self._recv_exact(session.sock, YMSG_HEADER_SIZE)
                if not header:
                    logger.info(f"Client {session.address} closed connection")
                    break

                # Get data length
                data_len = (header[8] << 8) | header[9]
                logger.debug(f"Header received, data_len={data_len}")

                # Read data
                if data_len > 0:
                    data = self._recv_exact(session.sock, data_len)
                    if not data:
                        break
                    raw = header + data
                else:
                    raw = header

                # Decode and handle
                packet = decode_packet(raw)
                if packet:
                    logger.info(f"Received: service={packet.service}, data={packet.data}")
                    self._handle_packet(session, packet)
                else:
                    logger.warning(f"Invalid packet from {session.address}")

        except Exception as e:
            logger.error(f"Error handling client: {e}")
        finally:
            if session.username:
                self.username_to_session.pop(session.username, None)
            with self.sessions_lock:
                self.sessions.pop(session.session_id, None)
            session.close()
            logger.info(f"Client {session.address} disconnected")

    def _recv_exact(self, sock, n):
        data = b''
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
        return data

    def _handle_packet(self, session, packet):
        # Track client protocol version
        if packet.version:
            session.protocol_version = packet.version
            if packet.version == 16:
                logger.debug(f"Client using YMSG v16 (YM9+)")
            elif packet.version in (9, 10, 11):
                logger.debug(f"Client using YMSG v{packet.version} (YM5.x)")

        handlers = {
            Service.VERIFY: self._handle_verify,
            Service.AUTH: self._handle_auth,
            Service.AUTH_V16: self._handle_auth_v16,  # YM9+ auth (service 57)
            Service.AUTHRESP: self._handle_authresp,
            Service.PING: self._handle_ping,
            Service.MESSAGE: self._handle_message,
            Service.LOGOFF: self._handle_logoff,
        }

        handler = handlers.get(packet.service)
        if handler:
            handler(session, packet)
        else:
            logger.warning(f"Unhandled service: {packet.service}")

    def _handle_verify(self, session, packet):
        logger.info("Handling VERIFY")
        session.send_packet(Service.VERIFY, status=1)

    def _handle_auth(self, session, packet):
        """Handle YM5.x auth (service 87)"""
        username = packet.data.get('1', '')
        session.username = username
        self.username_to_session[username] = session.session_id
        logger.info(f"Auth request from {username} (YM5.x style)")

        session.send_packet(
            Service.AUTH,
            status=1,
            data={
                '1': username,
                '94': 'DISCORD_BRIDGE_CHALLENGE'
            }
        )

    def _handle_auth_v16(self, session, packet):
        """Handle YM9+ auth (service 57)"""
        username = packet.data.get('1', '')
        session.username = username
        self.username_to_session[username] = session.session_id
        logger.info(f"Auth request from {username} (YM9 v16 style)")

        # Generate challenge
        challenge = hashlib.md5(f"{username}{time.time()}".encode()).hexdigest()

        # Key 13 = 2 means token-based auth
        session.send_packet(
            Service.AUTH_V16,
            status=1,
            data={
                '1': username,
                '13': '2',
                '94': challenge
            }
        )
        logger.info(f"Sent v16 auth challenge to {username}")

    def _handle_authresp(self, session, packet):
        username = packet.data.get('1', session.username)
        session.username = username
        session.authenticated = True
        logger.info(f"User {username} authenticated!")

        # Send LOGON
        logon_data = {
            '0': username,
            '1': username,
            '8': '0'
        }
        session.send_packet(Service.LOGON, status=0, data=logon_data)

        # Send buddy list
        friend_groups_str = self._encode_friend_groups()
        list_data = {
            '87': friend_groups_str,
            '88': '',
            '89': '',
            '3': username,
            '90': '1',
            '100': '0',
            '101': '',
            '102': '',
            '93': '86400'
        }
        session.send_packet(Service.LIST, status=1, data=list_data)
        logger.info(f"Sent buddy list to {username}")

    def _handle_ping(self, session, packet):
        session.send_packet(Service.PING, status=1)

    def _handle_message(self, session, packet):
        to_user = packet.data.get('5', '')
        message = packet.data.get('14', '')
        message = strip_yahoo_formatting(message)
        message = yahoo_to_discord(message)
        logger.info(f"Message from {session.username} to {to_user}: {message}")

    def _handle_logoff(self, session, packet):
        logger.info(f"User {session.username} logging off")
        session.close()

    def _encode_friend_groups(self):
        lines = []
        for group, friends in self.friend_groups.items():
            if friends:
                lines.append(f"{group}:{','.join(friends)}")
        return '\n'.join(lines)


if __name__ == '__main__':
    print("=" * 60)
    print("Yahoo Messenger Standalone Server")
    print("Supports YM 5.x and YM 9.x")
    print("=" * 60)

    # Start HTTP/HTTPS server for YM9 authentication
    print("\nStarting HTTP/HTTPS server for YM9 auth...")
    http_server = YahooHTTPServer(http_port=80, https_port=443)
    http_server.start()

    # Start YMSG server
    print("\nStarting YMSG server on port 5050...")
    server = StandaloneYMSGServer()
    thread = server.start()

    print("\nServers running. Press Ctrl+C to stop.")
    print("  - HTTP:  127.0.0.1:80  (YM9 capacity)")
    print("  - HTTPS: 127.0.0.1:443 (YM9 auth)")
    print("  - YMSG:  127.0.0.1:5050 (all versions)")
    print()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping...")
        server.running = False
        http_server.stop()
