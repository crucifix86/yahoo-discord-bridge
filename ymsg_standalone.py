#!/usr/bin/env python3
"""
Standalone YMSG Server - Runs on native Linux

This handles Yahoo Messenger client connections. The Discord side
runs separately under Wine.
"""

import socket
import threading
import logging
import json
import time
import os
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ymsg.protocol import (
    YMSGPacket, encode_packet, decode_packet,
    YMSG_HEADER_SIZE, Service, Status
)
from mapping.smileys import yahoo_to_discord, strip_yahoo_formatting

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

    def send_packet(self, service, status=0, data=None):
        packet = YMSGPacket(
            service=service,
            status=status,
            session_id=self.session_id,
            data=data or {}
        )
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
        handlers = {
            Service.VERIFY: self._handle_verify,
            Service.AUTH: self._handle_auth,
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
        username = packet.data.get('1', '')
        session.username = username
        self.username_to_session[username] = session.session_id
        logger.info(f"Auth request from {username}")

        session.send_packet(
            Service.AUTH,
            status=1,
            data={
                '1': username,
                '94': 'DISCORD_BRIDGE_CHALLENGE'
            }
        )

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
    server = StandaloneYMSGServer()
    thread = server.start()

    print("YMSG Server running. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping...")
        server.running = False
