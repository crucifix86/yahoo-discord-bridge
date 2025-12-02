"""
YMSG Server - Threaded version for Wine compatibility

Uses standard sockets and threading instead of asyncio,
which has issues under Wine's IocpProactor.
"""

import socket
import threading
import logging
import queue
from typing import Dict, Optional, Callable

from .protocol import (
    YMSGPacket, encode_packet, decode_packet,
    YMSG_HEADER_SIZE, Service, Status
)
from .chatroom import ChatRoomManager, ChatService

import sys
sys.path.insert(0, '..')
from mapping.smileys import yahoo_to_discord, strip_yahoo_formatting

logger = logging.getLogger(__name__)


class YMSGSession:
    """Represents a connected Yahoo Messenger client session"""

    def __init__(self, session_id: int, sock: socket.socket, addr):
        self.session_id = session_id
        self.sock = sock
        self.address = addr
        self.username: Optional[str] = None
        self.authenticated = False
        self.lock = threading.Lock()

    def send_packet(self, service: int, status: int = 0,
                    data: Dict[str, str] = None):
        """Send a YMSG packet to this client"""
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
                logger.debug(f"Sent to {self.username or self.address}: {packet}")
            except Exception as e:
                logger.error(f"Error sending to {self.username}: {e}")

    def send_raw(self, raw: bytes):
        """Send raw bytes to this client"""
        with self.lock:
            try:
                self.sock.sendall(raw)
            except Exception as e:
                logger.error(f"Error sending raw to {self.username}: {e}")

    def close(self):
        """Close the connection"""
        try:
            self.sock.close()
        except:
            pass


class YMSGServerThreaded:
    """
    Threaded YMSG Protocol Server

    Uses standard sockets and threading for Wine compatibility.
    """

    def __init__(self, host: str = '127.0.0.1', port: int = 5050):
        self.host = host
        self.port = port
        self.sessions: Dict[int, YMSGSession] = {}
        self.sessions_lock = threading.Lock()
        self.username_to_session: Dict[str, int] = {}
        self.session_counter = 0
        self.server_socket: Optional[socket.socket] = None
        self.running = False
        self.accept_thread: Optional[threading.Thread] = None

        # Callbacks for bridge integration (called from threads)
        self.on_login: Optional[Callable] = None
        self.on_logout: Optional[Callable] = None
        self.on_message: Optional[Callable] = None
        self.on_status_change: Optional[Callable] = None
        self.on_chat_message: Optional[Callable] = None
        self.on_chat_join: Optional[Callable] = None
        self.on_chat_leave: Optional[Callable] = None

        # Queue for async callbacks (to be processed by main loop)
        self.callback_queue = queue.Queue()

        # Friend data
        self.friend_groups: Dict[str, list] = {"Friends": []}
        self.friend_status: Dict[str, int] = {}

        # Chat room manager
        self.chat_rooms = ChatRoomManager()

    def start(self):
        """Start the YMSG server"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        self.running = True

        logger.info(f"YMSG Server (threaded) listening on {self.host}:{self.port}")

        # Start accept thread
        self.accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
        self.accept_thread.start()

    def stop(self):
        """Stop the YMSG server"""
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        logger.info("YMSG Server stopped")

    def _accept_loop(self):
        """Accept incoming connections"""
        logger.info("Accept loop started")
        while self.running:
            try:
                self.server_socket.settimeout(1.0)
                try:
                    client_sock, addr = self.server_socket.accept()
                except socket.timeout:
                    continue

                self.session_counter += 1
                session_id = self.session_counter

                session = YMSGSession(session_id, client_sock, addr)
                with self.sessions_lock:
                    self.sessions[session_id] = session

                logger.info(f"New connection from {addr}, session {session_id}")

                # Start client handler thread
                client_thread = threading.Thread(
                    target=self._handle_client,
                    args=(session,),
                    daemon=True
                )
                client_thread.start()

            except Exception as e:
                if self.running:
                    logger.error(f"Accept error: {e}")

    def _handle_client(self, session: YMSGSession):
        """Handle a client connection (runs in its own thread)"""
        try:
            while self.running:
                # Read header
                header = self._recv_exact(session.sock, YMSG_HEADER_SIZE)
                if not header:
                    break

                # Get data length from header
                data_len = (header[8] << 8) | header[9]

                # Read data if present
                if data_len > 0:
                    data = self._recv_exact(session.sock, data_len)
                    if not data:
                        break
                    raw = header + data
                else:
                    raw = header

                # Decode packet
                packet = decode_packet(raw)
                if not packet:
                    logger.warning(f"Invalid packet from {session.address}")
                    continue

                logger.debug(f"Received from {session.address}: {packet}")

                # Handle the packet
                self._handle_packet(session, packet)

        except ConnectionResetError:
            logger.info(f"Client {session.address} connection reset")
        except Exception as e:
            logger.error(f"Error handling client {session.address}: {e}")
        finally:
            # Cleanup
            if session.username:
                self.username_to_session.pop(session.username, None)
                self.chat_rooms.leave_all_rooms(session.session_id, session.username)
                if self.on_logout:
                    self.callback_queue.put(('logout', session.username))
            with self.sessions_lock:
                self.sessions.pop(session.session_id, None)
            session.close()
            logger.info(f"Client {session.address} disconnected")

    def _recv_exact(self, sock: socket.socket, n: int) -> Optional[bytes]:
        """Receive exactly n bytes"""
        data = b''
        while len(data) < n:
            try:
                chunk = sock.recv(n - len(data))
                if not chunk:
                    return None
                data += chunk
            except Exception:
                return None
        return data

    def _handle_packet(self, session: YMSGSession, packet: YMSGPacket):
        """Route packet to appropriate handler"""
        handlers = {
            Service.VERIFY: self._handle_verify,
            Service.AUTH: self._handle_auth,
            Service.AUTHRESP: self._handle_authresp,
            Service.PING: self._handle_ping,
            Service.MESSAGE: self._handle_message,
            Service.ISAWAY: self._handle_status_change,
            Service.ISBACK: self._handle_status_change,
            Service.NOTIFY: self._handle_notify,
            Service.LOGOFF: self._handle_logoff,
            ChatService.CHATJOIN: self._handle_chat_join,
            ChatService.CHATLEAVE: self._handle_chat_leave,
            ChatService.CHATMSG: self._handle_chat_message,
        }

        handler = handlers.get(packet.service)
        if handler:
            handler(session, packet)
        else:
            logger.warning(f"Unhandled service type: {packet.service}")

    def _handle_verify(self, session: YMSGSession, packet: YMSGPacket):
        """Handle initial handshake (service 76)"""
        logger.info(f"Received VERIFY from {session.address}")
        session.send_packet(Service.VERIFY, status=1)

    def _handle_auth(self, session: YMSGSession, packet: YMSGPacket):
        """Handle auth request (service 87)"""
        username = packet.data.get('1', '')
        session.username = username
        self.username_to_session[username] = session.session_id

        logger.info(f"Auth request from {username}")

        # Send challenge
        session.send_packet(
            Service.AUTH,
            status=1,
            data={
                '1': username,
                '94': 'DISCORD_BRIDGE_CHALLENGE'
            }
        )

    def _handle_authresp(self, session: YMSGSession, packet: YMSGPacket):
        """Handle auth response (service 84) - complete login"""
        username = packet.data.get('1', session.username)
        session.username = username
        session.authenticated = True

        logger.info(f"User {username} logged in (session {session.session_id})")

        # Build online friends list
        online_friends = []
        for friend, status in self.friend_status.items():
            if status != Status.OFFLINE:
                online_friends.append(friend)

        # Send LOGON response (service 1)
        logon_data = {
            '0': username,
            '1': username,
            '8': str(len(online_friends))
        }

        for friend in online_friends:
            logon_data['7'] = friend
            logon_data['10'] = str(self.friend_status.get(friend, 0))
            logon_data['11'] = '0'
            logon_data['17'] = '0'
            logon_data['13'] = '1'

        session.send_packet(Service.LOGON, status=0, data=logon_data)

        # Send buddy LIST (service 85)
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

        # Notify callback
        if self.on_login:
            self.callback_queue.put(('login', username))

    def _handle_ping(self, session: YMSGSession, packet: YMSGPacket):
        """Handle ping/keepalive (service 18)"""
        session.send_packet(Service.PING, status=1)

    def _handle_message(self, session: YMSGSession, packet: YMSGPacket):
        """Handle instant message (service 6)"""
        to_user = packet.data.get('5', '')
        from_user = packet.data.get('1', session.username)
        message = packet.data.get('14', '')

        # Strip Yahoo formatting tags
        message = strip_yahoo_formatting(message)

        # Convert Yahoo smileys to Discord emoji
        message = yahoo_to_discord(message)

        logger.info(f"Message from {from_user} to {to_user}: {message}")

        # Queue callback for Discord
        if self.on_message:
            self.callback_queue.put(('message', from_user, to_user, message))

    def _handle_status_change(self, session: YMSGSession, packet: YMSGPacket):
        """Handle status change"""
        status = packet.status
        custom_msg = packet.data.get('19', '')

        if self.on_status_change:
            self.callback_queue.put(('status', session.username, status, custom_msg))

    def _handle_notify(self, session: YMSGSession, packet: YMSGPacket):
        """Handle typing notification"""
        pass

    def _handle_logoff(self, session: YMSGSession, packet: YMSGPacket):
        """Handle logout"""
        logger.info(f"User {session.username} logged off")
        session.close()

    def _handle_chat_join(self, session: YMSGSession, packet: YMSGPacket):
        """Handle chat room join"""
        room_name = packet.data.get('104', '')
        username = session.username

        logger.info(f"User {username} joining room: {room_name}")

        if self.chat_rooms.join_room(session.session_id, username, room_name):
            room = self.chat_rooms.get_room(room_name)

            session.send_packet(
                ChatService.CHATJOIN,
                status=1,
                data={
                    '104': room_name,
                    '105': room.topic if room else '',
                    '106': room_name,
                    '108': username,
                    '109': username,
                    '112': '1'
                }
            )

            # Notify other users
            with self.sessions_lock:
                for other_session in self.sessions.values():
                    if other_session.session_id != session.session_id:
                        if other_session.authenticated:
                            rooms = self.chat_rooms.user_rooms.get(other_session.session_id, set())
                            if room_name in rooms:
                                other_session.send_packet(
                                    ChatService.CHATJOIN,
                                    status=1,
                                    data={
                                        '104': room_name,
                                        '109': username,
                                        '117': f'{username} has joined the room'
                                    }
                                )

            if self.on_chat_join:
                self.callback_queue.put(('chat_join', username, room_name))

    def _handle_chat_leave(self, session: YMSGSession, packet: YMSGPacket):
        """Handle chat room leave"""
        room_name = packet.data.get('104', '')
        username = session.username

        logger.info(f"User {username} leaving room: {room_name}")

        self.chat_rooms.leave_room(session.session_id, username, room_name)

        with self.sessions_lock:
            for other_session in self.sessions.values():
                if other_session.session_id != session.session_id:
                    if other_session.authenticated:
                        rooms = self.chat_rooms.user_rooms.get(other_session.session_id, set())
                        if room_name in rooms:
                            other_session.send_packet(
                                ChatService.CHATLEAVE,
                                status=1,
                                data={
                                    '104': room_name,
                                    '109': username
                                }
                            )

        if self.on_chat_leave:
            self.callback_queue.put(('chat_leave', username, room_name))

    def _handle_chat_message(self, session: YMSGSession, packet: YMSGPacket):
        """Handle chat room message"""
        room_name = packet.data.get('104', '')
        message = packet.data.get('117', '')
        from_user = session.username

        logger.info(f"Chat message in {room_name} from {from_user}: {message}")

        with self.sessions_lock:
            for other_session in self.sessions.values():
                if other_session.authenticated:
                    rooms = self.chat_rooms.user_rooms.get(other_session.session_id, set())
                    if room_name in rooms:
                        other_session.send_packet(
                            ChatService.CHATMSG,
                            status=1,
                            data={
                                '104': room_name,
                                '109': from_user,
                                '117': message,
                                '124': '1'
                            }
                        )

        if self.on_chat_message:
            self.callback_queue.put(('chat_message', from_user, room_name, message))

    def _encode_friend_groups(self) -> str:
        """Encode friend groups into YMSG format"""
        lines = []
        for group, friends in self.friend_groups.items():
            if friends:
                lines.append(f"{group}:{','.join(friends)}")
        return '\n'.join(lines)

    # Methods called by Discord bridge

    def send_message_to_client(self, from_user: str, to_user: str, message: str):
        """Send a message to a connected YM client"""
        session_id = self.username_to_session.get(to_user)
        if session_id:
            with self.sessions_lock:
                session = self.sessions.get(session_id)
            if session:
                session.send_packet(
                    Service.MESSAGE,
                    status=1,
                    data={
                        '4': from_user,
                        '5': to_user,
                        '14': message,
                        '63': ';0',
                        '64': '0',
                        '97': '1'
                    }
                )

    def send_friend_online(self, friend: str, status: int = 0):
        """Notify all clients that a friend came online"""
        self.friend_status[friend] = status
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

    def send_friend_offline(self, friend: str):
        """Notify all clients that a friend went offline"""
        self.friend_status[friend] = Status.OFFLINE
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

    def update_friends(self, friends: Dict[str, list], statuses: Dict[str, int]):
        """Update the friend list"""
        self.friend_groups = friends
        self.friend_status = statuses

    def send_chat_message(self, room_name: str, from_user: str, message: str):
        """Send a chat room message to all YM clients"""
        with self.sessions_lock:
            for session in self.sessions.values():
                if session.authenticated:
                    rooms = self.chat_rooms.user_rooms.get(session.session_id, set())
                    if room_name in rooms:
                        session.send_packet(
                            ChatService.CHATMSG,
                            status=1,
                            data={
                                '104': room_name,
                                '109': from_user,
                                '117': message,
                                '124': '1'
                            }
                        )

    def register_discord_channel(self, guild_id: int, guild_name: str,
                                  channel_id: int, channel_name: str) -> str:
        """Register a Discord channel as a chat room"""
        return self.chat_rooms.add_discord_channel(
            guild_id, guild_name, channel_id, channel_name
        )

    def get_room_by_channel(self, channel_id: int):
        """Get a chat room by its Discord channel ID"""
        return self.chat_rooms.get_room_by_channel(channel_id)

    def process_callbacks(self):
        """Process pending callbacks (call from main thread)"""
        while not self.callback_queue.empty():
            try:
                item = self.callback_queue.get_nowait()
                return item
            except queue.Empty:
                break
        return None
