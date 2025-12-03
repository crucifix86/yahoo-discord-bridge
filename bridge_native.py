#!/usr/bin/env python3
"""
Yahoo-Discord Bridge - Native Linux Version (Headless)

Runs YMSG server + Discord client on native Linux.
No GUI required.
"""

import asyncio
import threading
import logging
import json
import os
import sys
import socket
import time
import re
import sqlite3


def strip_emojis(text):
    """Remove emojis and special Unicode characters, keep ASCII-friendly names"""
    if not text:
        return text
    # Remove emojis and other non-ASCII characters
    cleaned = re.sub(r'[^\x00-\x7F]+', '', text)
    # Remove leading/trailing separators
    cleaned = cleaned.strip(' -_.')
    # Replace multiple spaces/dashes with single
    cleaned = re.sub(r'[-_\s]+', '-', cleaned)
    return cleaned if cleaned else 'general'

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ymsg.protocol import (
    YMSGPacket, encode_packet, decode_packet,
    YMSG_HEADER_SIZE, Service, Status
)
from mapping.smileys import yahoo_to_discord, strip_yahoo_formatting, discord_to_yahoo

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Load config
CONFIG_FILE = os.path.join(os.path.dirname(__file__), 'config.json')


class YMSGSession:
    def __init__(self, session_id, sock, addr):
        self.session_id = session_id
        self.sock = sock
        self.address = addr
        self.username = None
        self.authenticated = False
        self.lock = threading.Lock()
        self.protocol_version = 10  # Default to v10 for YM 5.x
        self.keepalive_thread = None
        self.keepalive_running = False

    def send_packet(self, service, status=0, data=None, session_id=None, data_list=None):
        packet = YMSGPacket(
            service=service,
            status=status,
            session_id=session_id if session_id is not None else self.session_id,
            data=data or {},
            data_list=data_list  # For packets with duplicate keys (like LIST_15)
        )
        packet.version = self.protocol_version  # Use client's version
        raw = encode_packet(packet)
        with self.lock:
            try:
                self.sock.sendall(raw)
                # Verbose hex logging for debugging
                hex_str = ' '.join(f'{b:02x}' for b in raw[:60])
                logger.info(f"SENT service={service} status={status} data={data} HEX[0:60]={hex_str}")
            except Exception as e:
                logger.error(f"Error sending: {e}")

    def start_keepalive(self):
        """Start sending periodic PING packets to keep connection alive"""
        if self.keepalive_thread and self.keepalive_running:
            return  # Already running
        self.keepalive_running = True
        self.keepalive_thread = threading.Thread(target=self._keepalive_loop, daemon=True)
        self.keepalive_thread.start()
        logger.info(f"Started keepalive for {self.username}")

    def _keepalive_loop(self):
        """Send KEEPALIVE packets to keep connection alive

        Sending KEEPALIVE every 10 seconds to try to keep connection open.
        For v16: KEEPALIVE (138) instead of PING (18)
        """
        # Send first KEEPALIVE immediately after login
        try:
            if self.protocol_version >= 16:
                # v16: Use KEEPALIVE (138) with username
                self.send_packet(Service.KEEPALIVE, status=0, data={'0': self.username})
                logger.info(f"Sent initial KEEPALIVE to {self.username}")
            else:
                self.send_packet(Service.PING, status=0, data={'143': '60', '144': '1'})
                logger.info(f"Sent initial PING to {self.username}")
        except Exception as e:
            logger.error(f"Initial keepalive failed: {e}")
            return

        while self.keepalive_running and self.authenticated:
            time.sleep(10)  # Send every 10 seconds
            if self.keepalive_running and self.authenticated:
                try:
                    if self.protocol_version >= 16:
                        self.send_packet(Service.KEEPALIVE, status=0, data={'0': self.username})
                    else:
                        self.send_packet(Service.PING, status=0, data={'143': '60', '144': '1'})
                    logger.debug(f"Sent keepalive to {self.username}")
                except Exception as e:
                    logger.error(f"Keepalive failed: {e}")
                    break

    def stop_keepalive(self):
        """Stop the keepalive thread"""
        self.keepalive_running = False

    def close(self):
        self.stop_keepalive()
        try:
            self.sock.close()
        except:
            pass


class NativeBridge:
    """Native Linux Yahoo-Discord Bridge"""

    def __init__(self, discord_token):
        self.discord_token = discord_token

        # YMSG Server
        self.host = '0.0.0.0'  # Listen on all interfaces for remote access
        self.port = 5050
        self.chat_port = 5101  # Separate chat server port
        self.sessions = {}
        self.sessions_lock = threading.Lock()
        self.username_to_session = {}
        self.session_counter = 0
        self.server_socket = None
        self.chat_server_socket = None  # Chat server socket
        self.running = False

        # Discord client (will be set up later)
        self.discord_client = None
        self.discord_loop = None

        # Friend data from Discord
        self.friend_groups = {"Friends": []}
        self.friend_status = {}
        self.friend_id_map = {}  # username -> discord user id

        # Chat room tracking
        self.channel_map = {}  # room_name -> discord channel
        self.chat_rooms = {}   # room_name -> set of session_ids in that room
        self.session_rooms = {}  # session_id -> set of room names

        # Offline message storage
        self.db_path = '/home/doug/yahoo-discord-bridge/offline_messages.db'
        self._init_offline_db()

    def _init_offline_db(self):
        """Initialize SQLite database for offline message storage"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS offline_messages
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      recipient TEXT NOT NULL,
                      sender TEXT NOT NULL,
                      message TEXT NOT NULL,
                      timestamp INTEGER NOT NULL)''')
        conn.commit()
        conn.close()
        logger.info(f"Offline message database initialized: {self.db_path}")

    def _store_offline_message(self, recipient, sender, message):
        """Store a message for offline delivery"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        timestamp = int(time.time())
        c.execute('INSERT INTO offline_messages (recipient, sender, message, timestamp) VALUES (?, ?, ?, ?)',
                  (recipient, sender, message, timestamp))
        conn.commit()
        conn.close()
        logger.info(f"Stored offline message for {recipient} from {sender}")

    def _get_offline_messages(self, recipient):
        """Get all pending offline messages for a user"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('SELECT id, sender, message, timestamp FROM offline_messages WHERE recipient = ? ORDER BY timestamp',
                  (recipient,))
        messages = c.fetchall()
        conn.close()
        return messages

    def _clear_offline_messages(self, recipient):
        """Clear offline messages after delivery"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('DELETE FROM offline_messages WHERE recipient = ?', (recipient,))
        conn.commit()
        conn.close()
        logger.info(f"Cleared offline messages for {recipient}")

    def _deliver_offline_messages(self, session):
        """Deliver pending offline messages to a newly logged in user"""
        messages = self._get_offline_messages(session.username)
        if not messages:
            return

        logger.info(f"Delivering {len(messages)} offline messages to {session.username}")

        # Build offline message packet with multiple messages
        # Format: [31][6], [32][6], [4]sender, [5]recipient, [14]message, [15]timestamp for each
        data_list = []
        for msg_id, sender, message, timestamp in messages:
            # Each message has these markers
            data_list.extend(['31', '6', '32', '6'])
            data_list.extend(['4', sender])
            data_list.extend(['5', session.username])
            formatted_msg = f'<font face="Tahoma">{message}'
            data_list.extend(['14', formatted_msg])
            data_list.extend(['15', str(timestamp)])
            data_list.extend(['97', '1'])

        # Send as single offline message packet with status=5 (OFFLINE5)
        session.send_packet(Service.MESSAGE, status=5, data_list=data_list)
        logger.info(f"Sent offline messages packet to {session.username}")

        # Clear delivered messages
        self._clear_offline_messages(session.username)

    def start(self):
        """Start the bridge"""
        # Start YMSG server
        self._start_ymsg_server()

        # Start Discord in separate thread
        discord_thread = threading.Thread(target=self._run_discord, daemon=True)
        discord_thread.start()

        logger.info("Bridge started! Waiting for connections...")

    def _start_ymsg_server(self):
        """Start the YMSG server"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        self.running = True

        logger.info(f"YMSG Server listening on {self.host}:{self.port}")

        accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
        accept_thread.start()

        # Start chat server on separate port
        self.chat_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.chat_server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.chat_server_socket.bind((self.host, self.chat_port))
        self.chat_server_socket.listen(5)

        logger.info(f"Chat Server listening on {self.host}:{self.chat_port}")

        chat_accept_thread = threading.Thread(target=self._chat_accept_loop, daemon=True)
        chat_accept_thread.start()

    def _accept_loop(self):
        """Accept incoming YMSG connections"""
        logger.info("Accept loop started")
        while self.running:
            try:
                client_sock, addr = self.server_socket.accept()
                logger.info(f"New connection from {addr}")

                # Enable TCP keepalive to prevent idle disconnects
                client_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                # On Linux: set keepalive idle time to 30 seconds
                if hasattr(socket, 'TCP_KEEPIDLE'):
                    client_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 30)
                if hasattr(socket, 'TCP_KEEPINTVL'):
                    client_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
                if hasattr(socket, 'TCP_KEEPCNT'):
                    client_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 5)

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

    def _chat_accept_loop(self):
        """Accept incoming chat connections on port 5101"""
        logger.info(f"Chat accept loop started on port {self.chat_port}")
        while self.running:
            try:
                client_sock, addr = self.chat_server_socket.accept()
                logger.info(f"New CHAT connection from {addr} on port {self.chat_port}")

                self.session_counter += 1
                session_id = self.session_counter

                session = YMSGSession(session_id, client_sock, addr)
                session.is_chat_session = True  # Mark as chat session
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
                    logger.error(f"Chat accept error: {e}")

    def _handle_client(self, session):
        """Handle a YMSG client connection"""
        try:
            while self.running:
                # Try to peek at data first
                session.sock.settimeout(300.0)  # 5 minute timeout for idle connections
                header = self._recv_exact(session.sock, YMSG_HEADER_SIZE)
                if not header:
                    logger.warning(f"Client {session.address} closed connection (no header received)")
                    break

                # Log raw header for debugging
                hex_header = ' '.join(f'{b:02x}' for b in header)
                logger.info(f"RAW HEADER from {session.address}: {hex_header}")

                # Check if it starts with YMSG magic
                if header[:4] != b'YMSG':
                    logger.warning(f"Invalid YMSG header from {session.address}: {header[:20]}")
                    break

                data_len = (header[8] << 8) | header[9]

                if data_len > 0:
                    data = self._recv_exact(session.sock, data_len)
                    if not data:
                        break
                    raw = header + data
                else:
                    raw = header

                packet = decode_packet(raw)
                if packet:
                    # Log client's session ID for debugging
                    logger.info(f"Client packet: service={packet.service} client_session_id=0x{packet.session_id:x} our_session_id={session.session_id}")

                    # Track client's protocol version
                    # Some clients send version in different byte order
                    version = packet.version
                    if version > 20:
                        # Byte order issue - extract actual version
                        version = version >> 8  # High byte is the real version
                    if version:
                        session.protocol_version = version
                        logger.info(f"Client using YMSG v{version}")
                    logger.debug(f"Received: service={packet.service}")
                    self._handle_packet(session, packet)

        except Exception as e:
            logger.error(f"Error handling client: {e}")
        finally:
            if session.username:
                self.username_to_session.pop(session.username, None)
            with self.sessions_lock:
                self.sessions.pop(session.session_id, None)
            session.close()
            logger.info(f"Client disconnected")

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
            # Conference services
            Service.CONFINVITE: self._handle_conference,
            Service.CONFLOGON: self._handle_conference,
            Service.CONFDECLINE: self._handle_conference,
            Service.CONFLOGOFF: self._handle_conference,
            Service.CONFMSG: self._handle_confmsg,
            # Chat room services
            Service.CHATONLINE: self._handle_chat,
            Service.CHATGOTO: self._handle_chat,
            Service.CHATJOIN: self._handle_chatjoin,
            Service.CHATLEAVE: self._handle_chat,
            Service.CHATMSG: self._handle_chatmsg,
            Service.CHATPING: self._handle_chatping,
            # YM9 specific services
            Service.SKINNAME: self._handle_skinname,
            Service.Y7_CHAT_SESSION: self._handle_y7_chat_session,
        }

        handler = handlers.get(packet.service)
        if handler:
            handler(session, packet)
        else:
            # Log unknown services for debugging
            logger.info(f"UNKNOWN SERVICE {packet.service}: status={packet.status} data={packet.data}")

    def _handle_verify(self, session, packet):
        logger.info("VERIFY handshake")
        session.send_packet(Service.VERIFY, status=1)

    def _handle_auth(self, session, packet):
        username = packet.data.get('1', '')
        session.username = username
        self.username_to_session[username] = session.session_id
        logger.info(f"Auth request from {username}")

        # Generate a challenge string for authentication
        import random
        import string
        challenge = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
        session.auth_challenge = challenge  # Store for later verification

        if session.protocol_version >= 16:
            # For YMSG v16 (YM 9), send challenge with key 13=2 to trigger HTTPS web auth
            # Client will then:
            #   1. GET https://login.yahoo.com/config/pwtoken_get?login=USER&passwd=PASS&chal=CHALLENGE
            #   2. GET https://login.yahoo.com/config/pwtoken_login?token=TOKEN
            #   3. Send AUTHRESP (0x54) with Y/T cookies
            logger.info(f"Sending AUTH challenge for YMSG v{session.protocol_version} (web auth)")
            session.send_packet(
                Service.AUTH,
                status=1,
                data={
                    '1': username,
                    '94': challenge,
                    '13': '2'  # Auth method: 2 = web-based token auth
                }
            )
        else:
            # For older clients (v10-15), send challenge and wait for AUTHRESP
            session.send_packet(
                Service.AUTH,
                status=1,
                data={'1': username, '94': challenge}
            )

    def _complete_login(self, session, username):
        """Complete login for a user (shared between auto-login and AUTHRESP)"""
        session.username = username
        session.authenticated = True
        logger.info(f"User {username} authenticated!")

        # Send login confirmation packets
        online_friends = [f for f, s in self.friend_status.items() if s != Status.OFFLINE]

        # Note: For v16, we skip sending AUTHRESP - it's client->server only
        # The server confirms login by sending LIST then LOGON
        if session.protocol_version >= 16:
            logger.info(f"v16 client - skipping server AUTHRESP")

        # Send buddy list FIRST (openymsg says it arrives before LOGON)
        friend_groups_str = self._encode_friend_groups()

        # Use LIST_15 (241) for v16 - required for login to work
        # LIST_15 format from openymsg test packet:
        # [302][318][300][318][65][GroupName]     <- Start group
        # [302][319][300][319][7][buddy1]         <- First buddy
        # [301][319][300][319][7][buddy2]         <- Subsequent buddies
        # [301][319][303][319]                    <- End buddies in group
        # [301][318][303][318]                    <- End group/list
        if session.protocol_version >= 16:
            all_friends = self.friend_groups.get('Friends', [])
            data_items = []

            # Add group with buddies
            if all_friends:
                # Group header: 302=318, 300=318
                data_items.extend(['302', '318', '300', '318'])
                # Group name: 65=Friends
                data_items.extend(['65', 'Friends'])

                # Add each buddy
                first_buddy = True
                for friend in all_friends:
                    if first_buddy:
                        # First buddy in group: 302=319, 300=319, 7=name
                        data_items.extend(['302', '319', '300', '319'])
                        first_buddy = False
                    else:
                        # Subsequent buddies: 301=319, 300=319, 7=name
                        data_items.extend(['301', '319', '300', '319'])
                    data_items.extend(['7', friend])

                # End buddies in group: 301=319, 303=319
                data_items.extend(['301', '319', '303', '319'])
                # End group: 301=318, 303=318
                data_items.extend(['301', '318', '303', '318'])

            # ALSO send regular LIST (85) to trigger client's loginComplete()
            # OpenYMSG only registers for LIST, not LIST_15, so we need both
            list_data = {
                '87': self._encode_friend_groups(),
                '88': '',
                '89': '',
                '3': username,
                '90': '1',
                '100': '0',
                '101': '',
                '102': '',
                '93': '86400',
                '59': 'B=abc123&b=abc456',
            }
            session.send_packet(Service.LIST, status=0, data=list_data)
            logger.info(f"Sent LIST (85) to trigger loginComplete()")

            session.send_packet(Service.LIST_15, status=0, data_list=data_items)
            logger.info(f"Sent LIST_15 (v16) with {len(all_friends)} buddies in structured format")
        else:
            list_data = {
                '87': friend_groups_str,
                '88': '',
                '89': '',
                '3': username,
                '90': '1',
                '100': '0',
                '101': '',
                '102': '',
                '93': '86400',
                '59': 'B=abc123&b=abc456',
            }
            session.send_packet(Service.LIST, status=1, data=list_data)
            logger.info(f"Sent LIST (v10) with {len(self.friend_groups.get('Friends', []))} friends")

        # Send LOGON after LIST
        logon_data = {
            '0': username,
            '1': username,
            '3': username,
            '8': str(len(online_friends)),
        }
        session.send_packet(Service.LOGON, status=0, data=logon_data)
        logger.info(f"Sent LOGON for {username} (v{session.protocol_version})")

        # Send online status for each online friend
        # For v16 clients, STATUS_15 also needs structured format:
        # [302][315][300][315][7][user][10][status][13][1][241][0][244][6][301][315][303][315]
        if session.protocol_version >= 16:
            for friend in online_friends:
                status_val = self.friend_status.get(friend, 0)
                status_items = [
                    '302', '315', '300', '315',  # Start entry
                    '7', friend,                  # Username
                    '10', str(status_val),        # Status (0=online)
                    '13', '1',                    # Flag
                    '241', '0',                   # Protocol type (0=Yahoo)
                    '244', '6',                   # Some value
                    '301', '315', '303', '315'    # End entry
                ]
                session.send_packet(Service.STATUS_15, status=0, data_list=status_items)
            logger.info(f"Sent {len(online_friends)} STATUS_15 packets (structured) for v16 client")
        else:
            for friend in online_friends:
                session.send_packet(
                    Service.ISBACK,
                    status=1,
                    data={
                        '7': friend,
                        '10': str(self.friend_status.get(friend, 0)),
                        '11': '0',
                        '17': '1',
                        '13': '1'
                    }
                )
            logger.info(f"Sent {len(online_friends)} ISBACK packets for v10 client")

        # Send NEWMAIL packet (service 11) - part of login sequence
        # Field 9 = new mail count
        session.send_packet(11, status=0, data={'9': '0'})  # 0 new emails
        logger.info(f"Sent NEWMAIL (0 new messages) for {username}")

        # Start keepalive - server sends PING with 143=60, 144=1 to keep client connected
        session.start_keepalive()

        # Deliver any pending offline messages
        self._deliver_offline_messages(session)

    def _handle_authresp(self, session, packet):
        """Handle AUTHRESP from clients after challenge"""
        username = packet.data.get('1', packet.data.get('0', session.username))
        logger.info(f"AUTHRESP received from {username}, data keys: {list(packet.data.keys())}")
        logger.info(f"AUTHRESP data: {packet.data}")

        if session.protocol_version >= 16:
            # YM9 sends cookies after HTTPS auth:
            # key 277 = T cookie, key 278 = Y cookie, key 307 = crumb
            t_cookie = packet.data.get('277', '')
            y_cookie = packet.data.get('278', '')
            crumb = packet.data.get('307', '')
            logger.info(f"YM9 AUTHRESP: T={t_cookie[:30]}... Y={y_cookie[:30]}... crumb={crumb}")

            # Accept any cookies - we don't validate them
            # Just complete the login

        self._complete_login(session, username)

    def _handle_ping(self, session, packet):
        logger.info(f"PING received from {session.username}, sending PONG")
        session.send_packet(Service.PING, status=0, data={})

    def _handle_skinname(self, session, packet):
        """Handle SKINNAME (service 21) - client telemetry/settings
        YM9 sends this after login with performance data.
        Send acknowledgement back.
        """
        logger.info(f"SKINNAME received from {session.username}")
        # Echo back the same service as acknowledgement
        session.send_packet(Service.SKINNAME, status=0, data={})

    def _handle_y7_chat_session(self, session, packet):
        """Handle Y7_CHAT_SESSION (service 212) - chat session init
        YM9 sends this after login. Send acknowledgement.
        """
        logger.info(f"Y7_CHAT_SESSION received from {session.username}: {packet.data}")
        # Echo back as acknowledgement
        session.send_packet(Service.Y7_CHAT_SESSION, status=0, data={})

    def _handle_message(self, session, packet):
        """Handle message from YM -> Discord"""
        # Log all keys in received packet for debugging
        logger.info(f"Received MESSAGE packet keys: {list(packet.data.keys())}")
        logger.info(f"Received MESSAGE packet data: {packet.data}")

        from_user = packet.data.get('1', session.username)
        to_user = packet.data.get('5', '')
        raw_message = packet.data.get('14', '')
        message = strip_yahoo_formatting(raw_message)
        message = yahoo_to_discord(message)

        logger.info(f"Message from {session.username} to {to_user}: {message}")

        # Send MESSAGE_ACK (service 251/0xfb) - fake ACK from recipient
        # The ACK should look like it's FROM the recipient TO the sender
        # This tells the client "the recipient got your message"
        message_id = packet.data.get('429', '')
        ack_data = {
            '1': to_user,      # Field 1 = recipient (who "received" the message)
            '5': from_user,    # Field 5 = sender (who needs confirmation)
            '302': '430',
            '430': message_id,
            '303': '430',
            '450': '0',
        }
        session.send_packet(Service.MESSAGE_ACK, status=0, data=ack_data)
        logger.info(f"Sent MESSAGE_ACK (fake from {to_user}) for msgid={message_id}")

        # Forward to Discord
        if to_user in self.friend_users and self.discord_client:
            asyncio.run_coroutine_threadsafe(
                self._send_discord_dm(to_user, message),
                self.discord_loop
            )

    def _handle_logoff(self, session, packet):
        logger.info(f"User logging off")
        session.close()

    # Conference handlers (for 1:1 group chats / conferences)
    def _handle_conference(self, session, packet):
        """Handle conference invite/join/decline/leave - log for debugging"""
        logger.info(f"CONFERENCE service={packet.service} status={packet.status} data={packet.data}")
        # Conference keys typically:
        # 1 = your username, 50 = conference name, 51 = invited users, 52 = joined users
        # 57 = inviter, 58 = message

    def _handle_confmsg(self, session, packet):
        """Handle conference message"""
        logger.info(f"CONFMSG: {packet.data}")
        conf_name = packet.data.get('57', '')  # Conference ID
        sender = packet.data.get('1', session.username)
        message = packet.data.get('14', '')
        logger.info(f"Conference {conf_name} message from {sender}: {message}")

    # Chat room handlers
    def _handle_chat(self, session, packet):
        """Handle chat room operations (CHATONLINE - service 150)"""
        logger.info(f"CHATONLINE service={packet.service} status={packet.status} data={packet.data}")

        # Service 150 (CHATONLINE) - going online for chat
        # Per libyahoo2: client sends keys 1, 109, 6='abcde'
        # Response should trigger client to send CHATJOIN
        if packet.service == Service.CHATONLINE:
            username = packet.data.get('109', packet.data.get('1', session.username))
            room_indicator = packet.data.get('6', 'abcde')
            logger.info(f"CHATONLINE: {username} going online for chat (indicator={room_indicator})")

            # Try responding with success status=1 and echo back some keys
            session.send_packet(
                Service.CHATONLINE,  # 150
                status=1,  # Try status=1 for success
                data={
                    '0': '1',  # Success flag
                    '1': session.username,
                    '109': session.username,
                },
                session_id=session.session_id
            )
            logger.info(f"Sent CHATONLINE ack (status=1) for {session.username}")

    def _handle_chatjoin(self, session, packet):
        """Handle chat room join request (service 152)"""
        logger.info(f"CHATJOIN request: {packet.data}")
        room_name = packet.data.get('104', packet.data.get('57', ''))
        room_id = packet.data.get('129', '')  # Room serial/ID from client
        logger.info(f"User wants to join room: {room_name} (id={room_id})")

        # For CHATJOIN requests, respond directly with CHATJOIN
        if room_name and self.discord_client:
            asyncio.run_coroutine_threadsafe(
                self._handle_discord_room_join(session, room_name, room_id=room_id),
                self.discord_loop
            )

    def _handle_chatping(self, session, packet):
        """Handle chat ping (service 161) - respond to keep chat alive"""
        username = packet.data.get('109', session.username)
        logger.info(f"CHATPING from {username}")
        # Respond with CHATPING echo
        session.send_packet(
            Service.CHATPING,  # 161
            status=0,
            data={'109': username},
            session_id=session.session_id
        )
        logger.info(f"Sent CHATPING response to {username}")

    def _handle_chatmsg(self, session, packet):
        """Handle chat room message"""
        logger.info(f"CHATMSG: {packet.data}")
        room_name = packet.data.get('104', packet.data.get('57', ''))
        message = packet.data.get('117', packet.data.get('14', ''))
        sender = packet.data.get('109', session.username)
        logger.info(f"Room {room_name} message from {sender}: {message}")

        # Forward to Discord channel
        if room_name and message and self.discord_client:
            asyncio.run_coroutine_threadsafe(
                self._send_discord_channel_msg(room_name, message),
                self.discord_loop
            )

    async def _handle_discord_room_join(self, session, room_name, room_id=''):
        """Handle CHATJOIN - joining a Discord channel as a Yahoo chat room"""
        # Keep the EXACT room name as sent by client (don't strip :1 suffix)
        # Strip emojis only for internal matching
        base_room_name = room_name.split(':')[0] if ':' in room_name else room_name
        clean_room_name = strip_emojis(base_room_name)
        channel_key = clean_room_name.lower()
        logger.info(f"Room join: original='{room_name}' room_id='{room_id}' -> key='{channel_key}'")

        # Find matching channel in Discord guilds
        channel = None
        for guild in self.discord_client.guilds:
            for ch in guild.text_channels:
                # Match by channel name after stripping emojis (case-insensitive)
                ch_clean = strip_emojis(ch.name).lower()
                if ch_clean == channel_key:
                    channel = ch
                    break
            if channel:
                break

        if channel:
            logger.info(f"Found Discord channel: {channel.name} in {channel.guild.name}")
            # Use ASCII-safe topic
            topic = strip_emojis(f"{channel.guild.name} - {channel.topic or 'Discord Channel'}")
        else:
            logger.info(f"No Discord channel found matching: {room_name}, creating virtual room")
            topic = f"Discord Bridge - {clean_room_name}"

        # Track room membership regardless
        if channel_key not in self.chat_rooms:
            self.chat_rooms[channel_key] = set()
        self.chat_rooms[channel_key].add(session.session_id)

        if session.session_id not in self.session_rooms:
            self.session_rooms[session.session_id] = set()
        self.session_rooms[session.session_id].add(channel_key)

        # Store channel mapping if we found one
        if channel:
            self.channel_map[channel_key] = channel

        # Use EXACT room name from client - don't modify it
        lobby_name = room_name

        # According to libyahoo2 source, CHATJOIN response must include:
        # - Field 104: room name
        # - Field 105: room topic
        # - Field 108: member count
        # - Field 109: member username (for each member)
        # - Field 110: member age
        # - Field 113: member flags (0 = normal user)
        # - Field 141: member alias (optional)
        # - Field 142: member location (optional)
        # - Field 130: first join indicator (1 = yes)
        #
        # Note: NOT sending CHATGOTO - YM 5.x handles chat on the same connection

        # CHATJOIN (152) - Multi-packet response for YM 5.x
        # Wireshark shows status=5 means "CONTINUED/More Packets"
        # Send packet 1 with room info (status=5), then packet 2 with members (status=1)

        # Packet 1: Room info with status=5 (more coming)
        room_info = {
            '1': session.username,
            '104': lobby_name,
            '105': topic[:100] if topic else 'Chat',
            '129': room_id if room_id else '1',
            '62': '2',
            '108': '1',  # 1 member
        }
        session.send_packet(
            Service.CHATJOIN,
            status=5,  # CONTINUED - more packets coming
            data=room_info,
            session_id=session.session_id
        )
        logger.info(f"Sent CHATJOIN(152) status=5 (continued) room='{lobby_name}'")

        # Packet 2: Member list with status=1 (final)
        member_info = {
            '1': session.username,
            '104': lobby_name,
            '109': session.username,
            '110': '0',
            '113': '0',
            '141': session.username,
            '142': '',
            '130': '1',
        }
        session.send_packet(
            Service.CHATJOIN,
            status=1,  # Final packet
            data=member_info,
            session_id=session.session_id
        )
        logger.info(f"Sent CHATJOIN(152) status=1 (final) room='{lobby_name}'")

    async def _send_discord_channel_msg(self, room_name, message):
        """Send message to Discord channel"""
        # Strip lobby suffix
        base_room_name = room_name.split(':')[0] if ':' in room_name else room_name
        channel_key = base_room_name.lower()

        if channel_key in self.channel_map:
            channel = self.channel_map[channel_key]
            try:
                await channel.send(message)
                logger.info(f"Sent to Discord channel {channel.name}: {message}")
            except Exception as e:
                logger.error(f"Failed to send to channel: {e}")

    def _forward_channel_to_ymsg(self, channel_name, sender_name, message):
        """Forward a Discord channel message to all Yahoo users in that room"""
        channel_key = channel_name.lower()
        if channel_key not in self.chat_rooms:
            return

        # Get all sessions in this room
        for session_id in self.chat_rooms[channel_key]:
            session = self.sessions.get(session_id)
            if session:
                # Send CHATMSG packet
                # Key 104 = room, 109 = sender, 117 = message
                session.send_packet(
                    Service.CHATMSG,
                    status=1,
                    data={
                        '1': sender_name,
                        '104': channel_name,
                        '109': sender_name,
                        '117': message
                    },
                    session_id=session.session_id
                )
        logger.info(f"Forwarded to {len(self.chat_rooms[channel_key])} Yahoo users: {sender_name}: {message}")

    def _encode_friend_groups(self):
        lines = []
        for group, friends in self.friend_groups.items():
            if friends:
                lines.append(f"{group}:{','.join(friends)}")
        return '\n'.join(lines)

    # Discord integration

    def _run_discord(self):
        """Run Discord client in its own thread with its own event loop"""
        import discord

        self.discord_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.discord_loop)

        class DiscordClient(discord.Client):
            def __init__(client_self, bridge):
                super().__init__()
                client_self.bridge = bridge

            async def on_ready(client_self):
                logger.info(f"Discord connected as {client_self.user.name}")
                client_self.bridge._load_friends(client_self)

            async def on_message(client_self, message):
                # Handle incoming messages
                if message.author == client_self.user:
                    return
                if isinstance(message.channel, discord.DMChannel):
                    # Handle DMs
                    sender_name = client_self.bridge._get_ymsg_name(message.author)
                    content = discord_to_yahoo(message.content)
                    logger.info(f"Discord DM from {sender_name}: {content}")
                    client_self.bridge._forward_to_ymsg(sender_name, content)
                elif hasattr(message.channel, 'guild'):
                    # Handle guild channel messages - forward to Yahoo chat rooms
                    channel_name = message.channel.name.lower()
                    sender_name = message.author.display_name
                    content = discord_to_yahoo(message.content)
                    if channel_name in client_self.bridge.chat_rooms:
                        logger.info(f"Discord channel {channel_name}: {sender_name}: {content}")
                        client_self.bridge._forward_channel_to_ymsg(channel_name, sender_name, content)

            async def on_presence_update(client_self, before, after):
                # Handle friend status changes
                # after can be a Relationship object - get the user from it
                user = after.user if hasattr(after, 'user') else after
                name = client_self.bridge._get_ymsg_name(user)
                if name in client_self.bridge.friend_status:
                    old_status = client_self.bridge.friend_status.get(name)
                    new_status = client_self.bridge._discord_status_to_ymsg(after.status)
                    if old_status != new_status:
                        client_self.bridge.friend_status[name] = new_status
                        if new_status == Status.OFFLINE:
                            client_self.bridge._notify_friend_offline(name)
                        else:
                            client_self.bridge._notify_friend_online(name, new_status)

        self.discord_client = DiscordClient(self)

        try:
            self.discord_loop.run_until_complete(
                self.discord_client.start(self.discord_token)
            )
        except Exception as e:
            logger.error(f"Discord error: {e}")

    def _load_friends(self, client):
        """Load friends from Discord"""
        friends = []
        self.friend_users = {}  # Store user objects for sending
        for relationship in client.relationships:
            if relationship.type.name == 'friend':
                user = relationship.user
                name = self._get_ymsg_name(user)
                friends.append(name)
                self.friend_id_map[name] = user.id
                self.friend_users[name] = user  # Store user object
                # Default to AVAILABLE - presence updates will correct this
                self.friend_status[name] = Status.AVAILABLE

        self.friend_groups = {"Friends": friends}
        logger.info(f"Loaded {len(friends)} Discord friends: {friends[:5]}...")

        # Save Discord guilds for chat room list
        self._save_guilds(client)

    def _get_ymsg_name(self, user):
        """Convert Discord user to YMSG-friendly name"""
        # Use username (without discriminator for new Discord)
        name = user.name.lower().replace(' ', '_')
        # Remove special chars
        name = ''.join(c for c in name if c.isalnum() or c == '_')
        return name[:32]  # YMSG username limit

    def _discord_status_to_ymsg(self, status):
        """Convert Discord status to YMSG status"""
        status_map = {
            'online': Status.AVAILABLE,
            'idle': Status.IDLE,
            'dnd': Status.BUSY,
            'offline': Status.OFFLINE,
            'invisible': Status.INVISIBLE,
        }
        return status_map.get(str(status), Status.AVAILABLE)

    async def _send_discord_dm(self, to_name, message):
        """Send a DM to a Discord user"""
        try:
            if to_name in self.friend_users:
                user = self.friend_users[to_name]
                await user.send(message)
                logger.info(f"Sent Discord DM to {user.name}")
            else:
                logger.error(f"User {to_name} not found in friend list")
        except Exception as e:
            logger.error(f"Failed to send Discord DM: {e}")

    def _forward_to_ymsg(self, sender, message):
        """Forward a message to connected YM clients, or store offline"""
        delivered = False
        with self.sessions_lock:
            logger.info(f"Forwarding to {len(self.sessions)} sessions")
            for session in self.sessions.values():
                if session.authenticated:
                    logger.info(f"Sending MESSAGE to {session.username} from {sender} (v{session.protocol_version})")
                    # For INCOMING messages: Key 4 = sender, Key 5 = recipient (you)
                    # This should route to the correct conversation window
                    formatted_msg = f'<font face="Tahoma">{message}'
                    session.send_packet(
                        Service.MESSAGE,
                        status=1,
                        data={
                            '4': sender,
                            '5': session.username,
                            '14': formatted_msg,
                            '97': '1',
                            '63': ';0',
                            '64': '0',
                            '1002': '1'
                        },
                        session_id=session.session_id
                    )
                    delivered = True

        # If no authenticated sessions, store for offline delivery
        # Use a default recipient - in a multi-user setup you'd want to specify this
        if not delivered:
            # Store for any user who might log in (using 'testuser' as default)
            # In a real setup, you'd track which Discord users map to which YM users
            self._store_offline_message('testuser', sender, message)
            logger.info(f"No online sessions - stored message from {sender} for offline delivery")

    def _notify_friend_online(self, friend, status):
        """Notify YM clients that a friend came online"""
        with self.sessions_lock:
            for session in self.sessions.values():
                if session.authenticated:
                    session.send_packet(
                        Service.ISBACK,
                        status=1,
                        data={
                            '7': friend,
                            '10': str(status),
                            '11': '0',
                            '17': '1',
                            '13': '1'
                        }
                    )

    def _notify_friend_offline(self, friend):
        """Notify YM clients that a friend went offline"""
        with self.sessions_lock:
            for session in self.sessions.values():
                if session.authenticated:
                    session.send_packet(
                        Service.LOGOFF,
                        status=1,
                        data={
                            '7': friend,
                            '10': str(Status.OFFLINE)
                        }
                    )

    def _save_guilds(self, client):
        """Save Discord guilds to JSON for HTTP server to read"""
        guilds_data = []
        for guild in client.guilds:
            channels = []
            for channel in guild.text_channels:
                channels.append({
                    'id': str(channel.id),
                    'name': channel.name,
                    'topic': channel.topic or ''
                })
            guilds_data.append({
                'id': str(guild.id),
                'name': guild.name,
                'channels': channels
            })

        # Save to JSON file
        guilds_file = os.path.join(os.path.dirname(__file__), 'discord_guilds.json')
        with open(guilds_file, 'w') as f:
            json.dump(guilds_data, f, indent=2)
        logger.info(f"Saved {len(guilds_data)} Discord guilds to {guilds_file}")


def main():
    # Load config
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE) as f:
            config = json.load(f)
        token = config.get('discord_token', '')
    else:
        token = os.environ.get('DISCORD_TOKEN', '')

    if not token:
        print("Error: No Discord token found!")
        print("Set DISCORD_TOKEN env var or create config.json with discord_token")
        sys.exit(1)

    bridge = NativeBridge(token)
    bridge.start()

    print("\n=== Yahoo-Discord Bridge (Native) ===")
    print("YMSG Server: 127.0.0.1:5050")
    print("Press Ctrl+C to stop\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping...")
        bridge.running = False


if __name__ == '__main__':
    main()
