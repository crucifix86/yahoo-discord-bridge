"""
YMSG Chat Room Support

Handles mapping Discord channels to Yahoo Messenger chat rooms.

YMSG Chat Services:
- 150 (CHATJOIN): Join a room
- 151 (CHATLEAVE): Leave a room
- 152 (CHATMSG): Message in room
- 155 (CHATPM): PM from room context
"""

import logging
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class ChatRoom:
    """Represents a YMSG chat room mapped to a Discord channel"""
    name: str                          # Room name shown in YM
    discord_guild_id: int              # Discord server ID
    discord_channel_id: int            # Discord channel ID
    discord_guild_name: str            # Discord server name
    discord_channel_name: str          # Discord channel name
    users: Set[str] = field(default_factory=set)  # Current users in room
    topic: str = ""


class ChatRoomManager:
    """
    Manages chat rooms and their Discord channel mappings.

    Yahoo Messenger chat room names are formatted as:
    "ServerName:ChannelName" or just "ChannelName" for a default server
    """

    def __init__(self):
        # room_name -> ChatRoom
        self.rooms: Dict[str, ChatRoom] = {}

        # discord_channel_id -> room_name
        self.channel_to_room: Dict[int, str] = {}

        # session_id -> set of room names user is in
        self.user_rooms: Dict[int, Set[str]] = {}

    def add_discord_channel(self, guild_id: int, guild_name: str,
                            channel_id: int, channel_name: str) -> str:
        """
        Register a Discord channel as a chat room.
        Returns the room name.
        """
        # Create room name: "ServerName:ChannelName"
        room_name = f"{guild_name}:{channel_name}"

        # Sanitize for YMSG (remove special chars)
        room_name = self._sanitize_room_name(room_name)

        room = ChatRoom(
            name=room_name,
            discord_guild_id=guild_id,
            discord_channel_id=channel_id,
            discord_guild_name=guild_name,
            discord_channel_name=channel_name
        )

        self.rooms[room_name] = room
        self.channel_to_room[channel_id] = room_name

        logger.debug(f"Registered room: {room_name} -> channel {channel_id}")
        return room_name

    def _sanitize_room_name(self, name: str) -> str:
        """Sanitize room name for YMSG compatibility"""
        # Replace problematic characters
        name = name.replace('\n', ' ').replace('\r', ' ')
        # Limit length
        if len(name) > 64:
            name = name[:64]
        return name

    def get_room_list(self) -> List[Dict]:
        """
        Get list of available rooms for YMSG client.
        Format matches Yahoo chat room lobby format.
        """
        room_list = []
        for room in self.rooms.values():
            room_list.append({
                'name': room.name,
                'topic': room.topic or room.discord_channel_name,
                'users': len(room.users),
                'category': room.discord_guild_name
            })
        return room_list

    def get_room(self, room_name: str) -> Optional[ChatRoom]:
        """Get a room by name"""
        return self.rooms.get(room_name)

    def get_room_by_channel(self, channel_id: int) -> Optional[ChatRoom]:
        """Get a room by Discord channel ID"""
        room_name = self.channel_to_room.get(channel_id)
        if room_name:
            return self.rooms.get(room_name)
        return None

    def join_room(self, session_id: int, username: str, room_name: str) -> bool:
        """User joins a chat room"""
        room = self.rooms.get(room_name)
        if not room:
            logger.warning(f"Room not found: {room_name}")
            return False

        room.users.add(username)

        if session_id not in self.user_rooms:
            self.user_rooms[session_id] = set()
        self.user_rooms[session_id].add(room_name)

        logger.info(f"User {username} joined room {room_name}")
        return True

    def leave_room(self, session_id: int, username: str, room_name: str):
        """User leaves a chat room"""
        room = self.rooms.get(room_name)
        if room:
            room.users.discard(username)

        if session_id in self.user_rooms:
            self.user_rooms[session_id].discard(room_name)

        logger.info(f"User {username} left room {room_name}")

    def leave_all_rooms(self, session_id: int, username: str):
        """User leaves all rooms (on disconnect)"""
        if session_id in self.user_rooms:
            for room_name in list(self.user_rooms[session_id]):
                self.leave_room(session_id, username, room_name)
            del self.user_rooms[session_id]

    def get_users_in_room(self, room_name: str) -> List[str]:
        """Get list of users in a room"""
        room = self.rooms.get(room_name)
        if room:
            return list(room.users)
        return []


# YMSG Chat Protocol Constants

class ChatService:
    """YMSG Chat service types"""
    CHATJOIN = 150      # Join room
    CHATLEAVE = 151     # Leave room
    CHATMSG = 152       # Room message
    CHATADDINVITE = 153 # Invite to room
    CHATLOGOUT = 154    # Chat logout
    CHATPING = 161      # Chat ping
    CHATLOGON = 162     # Chat logon


class ChatKey:
    """YMSG Chat key fields"""
    ROOM = '104'        # Room name
    ROOM_TOPIC = '105'  # Room topic
    ROOM_URL = '106'    # Room URL/category
    FROM = '109'        # Message sender
    TO = '110'          # Message recipient
    MESSAGE = '117'     # Message content
    MSGTYPE = '124'     # Message type


def encode_chat_join_response(room_name: str, username: str,
                               users: List[str], topic: str = "") -> Dict[str, str]:
    """Encode a chat join response packet data"""
    data = {
        '104': room_name,
        '105': topic,
        '106': room_name,  # category/URL
        '108': username,   # Current user
        '109': username,
        '112': '1',        # Room flags
    }

    # Add users in room
    for i, user in enumerate(users):
        data[f'109'] = user  # Each user

    return data


def encode_chat_message(room_name: str, from_user: str,
                        message: str) -> Dict[str, str]:
    """Encode a chat room message packet data"""
    return {
        '104': room_name,
        '109': from_user,
        '117': message,
        '124': '1'  # Message type: regular
    }
