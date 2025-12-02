"""
YMSG Server - Accepts connections from Yahoo Messenger clients

Handles the YMSG protocol and bridges to Discord.
"""

import asyncio
import logging
from typing import Dict, Optional, Callable, Any

from .protocol import (
    YMSGPacket, encode_packet, decode_packet, encode_data_list,
    YMSG_HEADER_SIZE, Service, Status
)
from .chatroom import ChatRoomManager, ChatService, encode_chat_message

import sys
sys.path.insert(0, '..')
from mapping.smileys import yahoo_to_discord, strip_yahoo_formatting

logger = logging.getLogger(__name__)


class YMSGSession:
    """Represents a connected Yahoo Messenger client session"""

    def __init__(self, session_id: int, reader: asyncio.StreamReader,
                 writer: asyncio.StreamWriter):
        self.session_id = session_id
        self.reader = reader
        self.writer = writer
        self.username: Optional[str] = None
        self.authenticated = False
        self.address = writer.get_extra_info('peername')

    async def send_packet(self, service: int, status: int = 0,
                          data: Dict[str, str] = None):
        """Send a YMSG packet to this client"""
        packet = YMSGPacket(
            service=service,
            status=status,
            session_id=self.session_id,
            data=data or {}
        )
        raw = encode_packet(packet)
        self.writer.write(raw)
        await self.writer.drain()
        logger.debug(f"Sent to {self.username or self.address}: {packet}")

    async def send_raw(self, raw: bytes):
        """Send raw bytes to this client"""
        self.writer.write(raw)
        await self.writer.drain()

    def close(self):
        """Close the connection"""
        self.writer.close()


class YMSGServer:
    """
    YMSG Protocol Server

    Listens for Yahoo Messenger client connections and handles
    the protocol, bridging messages to/from Discord.
    """

    def __init__(self, host: str = '127.0.0.1', port: int = 5050):
        self.host = host
        self.port = port
        self.sessions: Dict[int, YMSGSession] = {}
        self.username_to_session: Dict[str, int] = {}
        self.session_counter = 0
        self.server: Optional[asyncio.Server] = None

        # Callbacks for bridge integration
        self.on_login: Optional[Callable] = None
        self.on_logout: Optional[Callable] = None
        self.on_message: Optional[Callable] = None
        self.on_status_change: Optional[Callable] = None
        self.on_chat_message: Optional[Callable] = None  # Chat room messages
        self.on_chat_join: Optional[Callable] = None
        self.on_chat_leave: Optional[Callable] = None

        # Friend data (populated by Discord bridge)
        self.friend_groups: Dict[str, list] = {"Friends": []}
        self.friend_status: Dict[str, int] = {}

        # Chat room manager
        self.chat_rooms = ChatRoomManager()

    async def start(self):
        """Start the YMSG server"""
        self.server = await asyncio.start_server(
            self._handle_client,
            self.host,
            self.port
        )
        addr = self.server.sockets[0].getsockname()
        logger.info(f"YMSG Server listening on {addr[0]}:{addr[1]}")
        # Start serving in background task
        asyncio.create_task(self.server.serve_forever())

    async def stop(self):
        """Stop the YMSG server"""
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            logger.info("YMSG Server stopped")

    async def _handle_client(self, reader: asyncio.StreamReader,
                             writer: asyncio.StreamWriter):
        """Handle a new client connection"""
        self.session_counter += 1
        session_id = self.session_counter

        session = YMSGSession(session_id, reader, writer)
        self.sessions[session_id] = session

        addr = writer.get_extra_info('peername')
        logger.info(f"New connection from {addr}, session {session_id}")

        try:
            while True:
                # Read header
                header = await reader.readexactly(YMSG_HEADER_SIZE)

                # Get data length from header
                data_len = (header[8] << 8) | header[9]

                # Read data if present
                if data_len > 0:
                    data = await reader.read(data_len)
                    raw = header + data
                else:
                    raw = header

                # Decode packet
                packet = decode_packet(raw)
                if not packet:
                    logger.warning(f"Invalid packet from {addr}")
                    continue

                logger.debug(f"Received from {addr}: {packet}")

                # Handle the packet
                await self._handle_packet(session, packet)

        except asyncio.IncompleteReadError:
            logger.info(f"Client {addr} disconnected")
        except ConnectionResetError:
            logger.info(f"Client {addr} connection reset")
        except Exception as e:
            logger.error(f"Error handling client {addr}: {e}")
        finally:
            # Cleanup
            if session.username:
                self.username_to_session.pop(session.username, None)
                # Leave all chat rooms
                self.chat_rooms.leave_all_rooms(session_id, session.username)
                if self.on_logout:
                    await self.on_logout(session.username)
            self.sessions.pop(session_id, None)
            writer.close()

    async def _handle_packet(self, session: YMSGSession, packet: YMSGPacket):
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
            # Chat room services
            ChatService.CHATJOIN: self._handle_chat_join,
            ChatService.CHATLEAVE: self._handle_chat_leave,
            ChatService.CHATMSG: self._handle_chat_message,
        }

        handler = handlers.get(packet.service)
        if handler:
            await handler(session, packet)
        else:
            logger.warning(f"Unhandled service type: {packet.service}")

    async def _handle_verify(self, session: YMSGSession, packet: YMSGPacket):
        """Handle initial handshake (service 76)"""
        await session.send_packet(Service.VERIFY, status=1)

    async def _handle_auth(self, session: YMSGSession, packet: YMSGPacket):
        """Handle auth request - client sends username (service 87)"""
        username = packet.data.get('1', '')
        session.username = username
        self.username_to_session[username] = session.session_id

        # Send challenge (for now, fake challenge - auth is handled by Discord)
        await session.send_packet(
            Service.AUTH,
            status=1,
            data={
                '1': username,
                '94': 'DISCORD_BRIDGE_CHALLENGE'  # Fake challenge
            }
        )

    async def _handle_authresp(self, session: YMSGSession, packet: YMSGPacket):
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

        # Add online friends to logon data
        for i, friend in enumerate(online_friends):
            logon_data['7'] = friend
            logon_data['10'] = str(self.friend_status.get(friend, 0))
            logon_data['11'] = '0'
            logon_data['17'] = '0'
            logon_data['13'] = '1'

        await session.send_packet(Service.LOGON, status=0, data=logon_data)

        # Send buddy LIST (service 85)
        friend_groups_str = self._encode_friend_groups()
        list_data = {
            '87': friend_groups_str,
            '88': '',  # Ignore list
            '89': '',  # Aliases
            '3': username,
            '90': '1',
            '100': '0',
            '101': '',
            '102': '',
            '93': '86400'
        }
        await session.send_packet(Service.LIST, status=1, data=list_data)

        # Notify callback
        if self.on_login:
            await self.on_login(username)

    async def _handle_ping(self, session: YMSGSession, packet: YMSGPacket):
        """Handle ping/keepalive (service 18)"""
        await session.send_packet(Service.PING, status=1)

    async def _handle_message(self, session: YMSGSession, packet: YMSGPacket):
        """Handle instant message (service 6)"""
        to_user = packet.data.get('5', '')
        from_user = packet.data.get('1', session.username)
        message = packet.data.get('14', '')

        # Strip Yahoo formatting tags
        message = strip_yahoo_formatting(message)

        # Convert Yahoo smileys to Discord emoji
        message = yahoo_to_discord(message)

        logger.info(f"Message from {from_user} to {to_user}: {message}")

        # Forward to Discord via callback
        if self.on_message:
            await self.on_message(from_user, to_user, message)

    async def _handle_status_change(self, session: YMSGSession, packet: YMSGPacket):
        """Handle status change (services 3, 4)"""
        status = packet.status
        custom_msg = packet.data.get('19', '')

        if self.on_status_change:
            await self.on_status_change(session.username, status, custom_msg)

    async def _handle_notify(self, session: YMSGSession, packet: YMSGPacket):
        """Handle typing notification (service 75)"""
        # Could forward to Discord typing indicator
        pass

    async def _handle_logoff(self, session: YMSGSession, packet: YMSGPacket):
        """Handle logout (service 2)"""
        logger.info(f"User {session.username} logged off")
        session.close()

    def _encode_friend_groups(self) -> str:
        """Encode friend groups into YMSG format"""
        # Format: "GroupName:friend1,friend2,friend3\nGroup2:friend4\n"
        lines = []
        for group, friends in self.friend_groups.items():
            if friends:
                lines.append(f"{group}:{','.join(friends)}")
        return '\n'.join(lines)

    # Methods called by Discord bridge to update YM clients

    async def send_message_to_client(self, from_user: str, to_user: str, message: str):
        """Send a message to a connected YM client"""
        session_id = self.username_to_session.get(to_user)
        if session_id and session_id in self.sessions:
            session = self.sessions[session_id]
            await session.send_packet(
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

    async def send_friend_online(self, friend: str, status: int = 0):
        """Notify all connected clients that a friend came online"""
        self.friend_status[friend] = status
        for session in self.sessions.values():
            if session.authenticated:
                await session.send_packet(
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

    async def send_friend_offline(self, friend: str):
        """Notify all connected clients that a friend went offline"""
        self.friend_status[friend] = Status.OFFLINE
        for session in self.sessions.values():
            if session.authenticated:
                await session.send_packet(
                    Service.LOGOFF,
                    status=1,
                    data={
                        '7': friend,
                        '10': str(Status.OFFLINE)
                    }
                )

    def update_friends(self, friends: Dict[str, list], statuses: Dict[str, int]):
        """Update the friend list (called by Discord bridge)"""
        self.friend_groups = friends
        self.friend_status = statuses

    # Chat room handlers

    async def _handle_chat_join(self, session: YMSGSession, packet: YMSGPacket):
        """Handle chat room join request (service 150)"""
        room_name = packet.data.get('104', '')
        username = session.username

        logger.info(f"User {username} joining room: {room_name}")

        # Join the room
        if self.chat_rooms.join_room(session.session_id, username, room_name):
            room = self.chat_rooms.get_room(room_name)
            users = self.chat_rooms.get_users_in_room(room_name)

            # Send join confirmation
            await session.send_packet(
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

            # Notify other users in room
            for other_session in self.sessions.values():
                if other_session.session_id != session.session_id:
                    if other_session.authenticated:
                        rooms = self.chat_rooms.user_rooms.get(other_session.session_id, set())
                        if room_name in rooms:
                            await other_session.send_packet(
                                ChatService.CHATJOIN,
                                status=1,
                                data={
                                    '104': room_name,
                                    '109': username,
                                    '117': f'{username} has joined the room'
                                }
                            )

            # Callback to bridge
            if self.on_chat_join:
                await self.on_chat_join(username, room_name)

    async def _handle_chat_leave(self, session: YMSGSession, packet: YMSGPacket):
        """Handle chat room leave (service 151)"""
        room_name = packet.data.get('104', '')
        username = session.username

        logger.info(f"User {username} leaving room: {room_name}")

        self.chat_rooms.leave_room(session.session_id, username, room_name)

        # Notify other users in room
        for other_session in self.sessions.values():
            if other_session.session_id != session.session_id:
                if other_session.authenticated:
                    rooms = self.chat_rooms.user_rooms.get(other_session.session_id, set())
                    if room_name in rooms:
                        await other_session.send_packet(
                            ChatService.CHATLEAVE,
                            status=1,
                            data={
                                '104': room_name,
                                '109': username
                            }
                        )

        if self.on_chat_leave:
            await self.on_chat_leave(username, room_name)

    async def _handle_chat_message(self, session: YMSGSession, packet: YMSGPacket):
        """Handle chat room message (service 152)"""
        room_name = packet.data.get('104', '')
        message = packet.data.get('117', '')
        from_user = session.username

        logger.info(f"Chat message in {room_name} from {from_user}: {message}")

        # Forward to all users in room
        for other_session in self.sessions.values():
            if other_session.authenticated:
                rooms = self.chat_rooms.user_rooms.get(other_session.session_id, set())
                if room_name in rooms:
                    await other_session.send_packet(
                        ChatService.CHATMSG,
                        status=1,
                        data={
                            '104': room_name,
                            '109': from_user,
                            '117': message,
                            '124': '1'
                        }
                    )

        # Forward to Discord via callback
        if self.on_chat_message:
            await self.on_chat_message(from_user, room_name, message)

    # Methods for sending chat room messages from Discord

    async def send_chat_message(self, room_name: str, from_user: str, message: str):
        """Send a chat room message to all YM clients in the room"""
        for session in self.sessions.values():
            if session.authenticated:
                rooms = self.chat_rooms.user_rooms.get(session.session_id, set())
                if room_name in rooms:
                    await session.send_packet(
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
