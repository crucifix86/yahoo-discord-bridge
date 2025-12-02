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

    def send_packet(self, service, status=0, data=None, session_id=None):
        packet = YMSGPacket(
            service=service,
            status=status,
            session_id=session_id if session_id is not None else self.session_id,
            data=data or {}
        )
        packet.version = self.protocol_version  # Use client's version
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


class NativeBridge:
    """Native Linux Yahoo-Discord Bridge"""

    def __init__(self, discord_token):
        self.discord_token = discord_token

        # YMSG Server
        self.host = '0.0.0.0'  # Listen on all interfaces for remote access
        self.port = 5050
        self.sessions = {}
        self.sessions_lock = threading.Lock()
        self.username_to_session = {}
        self.session_counter = 0
        self.server_socket = None
        self.running = False

        # Discord client (will be set up later)
        self.discord_client = None
        self.discord_loop = None

        # Friend data from Discord
        self.friend_groups = {"Friends": []}
        self.friend_status = {}
        self.friend_id_map = {}  # username -> discord user id

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

    def _accept_loop(self):
        """Accept incoming YMSG connections"""
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
        """Handle a YMSG client connection"""
        try:
            while self.running:
                header = self._recv_exact(session.sock, YMSG_HEADER_SIZE)
                if not header:
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

        session.send_packet(
            Service.AUTH,
            status=1,
            data={'1': username, '94': 'DISCORD_BRIDGE_CHALLENGE'}
        )

    def _handle_authresp(self, session, packet):
        username = packet.data.get('1', session.username)
        session.username = username
        session.authenticated = True
        logger.info(f"User {username} authenticated!")

        # Send LOGON with online friends count
        online_friends = [f for f, s in self.friend_status.items() if s != Status.OFFLINE]
        logon_data = {
            '0': username,
            '1': username,
            '8': str(len(online_friends))
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
        logger.info(f"Sent buddy list with {len(self.friend_groups.get('Friends', []))} friends")

        # Send online status for each online friend
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

    def _handle_ping(self, session, packet):
        session.send_packet(Service.PING, status=1)

    def _handle_message(self, session, packet):
        """Handle message from YM -> Discord"""
        # Log all keys in received packet for debugging
        logger.info(f"Received MESSAGE packet keys: {list(packet.data.keys())}")
        logger.info(f"Received MESSAGE packet data: {packet.data}")

        to_user = packet.data.get('5', '')
        raw_message = packet.data.get('14', '')
        message = strip_yahoo_formatting(raw_message)
        message = yahoo_to_discord(message)

        logger.info(f"Message from {session.username} to {to_user}: {message}")

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
        """Handle chat room operations - log for debugging"""
        logger.info(f"CHAT service={packet.service} status={packet.status} data={packet.data}")
        # Chat room keys typically:
        # 1 = username, 104 = room name, 109 = user ID, 117 = message

    def _handle_chatjoin(self, session, packet):
        """Handle chat room join request"""
        logger.info(f"CHATJOIN request: {packet.data}")
        room_name = packet.data.get('104', packet.data.get('57', ''))
        logger.info(f"User wants to join room: {room_name}")

        # For now, acknowledge the join with the room info
        # This will need to map to a Discord channel
        if room_name and self.discord_client:
            # Try to find matching Discord channel
            asyncio.run_coroutine_threadsafe(
                self._handle_discord_room_join(session, room_name),
                self.discord_loop
            )

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

    async def _handle_discord_room_join(self, session, room_name):
        """Handle joining a Discord channel as a Yahoo chat room"""
        # Find matching channel in Discord guilds
        channel = None
        for guild in self.discord_client.guilds:
            for ch in guild.text_channels:
                # Match by channel name (case-insensitive)
                if ch.name.lower() == room_name.lower():
                    channel = ch
                    break
            if channel:
                break

        if channel:
            logger.info(f"Found Discord channel: {channel.name} in {channel.guild.name}")
            # Send join confirmation
            # Key 104 = room, 109 = user, 141 = room topic
            session.send_packet(
                Service.CHATJOIN,
                status=1,
                data={
                    '1': session.username,
                    '104': room_name,
                    '109': session.username,
                    '141': f"Discord: {channel.guild.name}",
                    '142': '0'  # user count placeholder
                },
                session_id=session.session_id
            )
            # Store channel mapping
            if not hasattr(self, 'channel_map'):
                self.channel_map = {}
            self.channel_map[room_name.lower()] = channel
        else:
            logger.info(f"No Discord channel found matching: {room_name}")

    async def _send_discord_channel_msg(self, room_name, message):
        """Send message to Discord channel"""
        if hasattr(self, 'channel_map') and room_name.lower() in self.channel_map:
            channel = self.channel_map[room_name.lower()]
            try:
                await channel.send(message)
                logger.info(f"Sent to Discord channel {channel.name}: {message}")
            except Exception as e:
                logger.error(f"Failed to send to channel: {e}")

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
                # Handle incoming DMs
                if message.author == client_self.user:
                    return
                if isinstance(message.channel, discord.DMChannel):
                    sender_name = client_self.bridge._get_ymsg_name(message.author)
                    content = discord_to_yahoo(message.content)
                    logger.info(f"Discord DM from {sender_name}: {content}")
                    client_self.bridge._forward_to_ymsg(sender_name, content)

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
        """Forward a message to connected YM clients"""
        import time as time_module
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
