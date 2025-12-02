"""
Discord Client - Connects to Discord as a user account

Uses discord.py-self to connect and fetch friends, presence, DMs.
"""

import asyncio
import logging
from typing import Dict, List, Optional, Callable

import discord
from discord import Status as DiscordStatus

logger = logging.getLogger(__name__)


class DiscordBridge(discord.Client):
    """
    Discord client that bridges to YMSG server.

    Connects as a user (not a bot) to access friends, DMs, etc.
    """

    def __init__(self, *args, **kwargs):
        # User accounts don't use intents like bots
        super().__init__(*args, **kwargs)

        # Callbacks for YMSG bridge
        self.on_friend_message: Optional[Callable] = None
        self.on_friend_online: Optional[Callable] = None
        self.on_friend_offline: Optional[Callable] = None
        self.on_friend_status_change: Optional[Callable] = None
        self.on_channel_message: Optional[Callable] = None  # Guild channel messages
        self.on_ready_callback: Optional[Callable] = None

        # Cache
        self._dm_channels: Dict[str, discord.DMChannel] = {}
        self._watched_channels: Dict[int, str] = {}  # channel_id -> room_name

    async def on_connect(self):
        """Called when we connect to Discord gateway"""
        logger.info("=== on_connect event triggered ===")

    async def on_ready(self):
        """Called when connected to Discord"""
        try:
            logger.info("=== on_ready event triggered ===")
            logger.info(f"Logged in as {self.user.name} ({self.user.id})")

            # Log friends count
            friends = self.friends
            logger.info(f"Found {len(friends)} friends")

            for friend in friends[:10]:  # Log first 10
                logger.debug(f"  - {friend.name}: {friend.status}")

            if self.on_ready_callback:
                logger.info("Calling on_ready_callback...")
                await self.on_ready_callback()
                logger.info("on_ready_callback completed")
        except Exception as e:
            logger.error(f"Error in on_ready: {e}")
            import traceback
            logger.error(traceback.format_exc())

    async def on_message(self, message: discord.Message):
        """Handle incoming messages"""
        # Ignore our own messages
        if message.author == self.user:
            return

        # Handle DMs
        if isinstance(message.channel, discord.DMChannel):
            sender = message.author.name
            content = message.content

            logger.info(f"DM from {sender}: {content}")

            if self.on_friend_message:
                await self.on_friend_message(sender, content)

        # Handle guild channel messages (for chat rooms)
        elif isinstance(message.channel, discord.TextChannel):
            channel_id = message.channel.id
            if channel_id in self._watched_channels:
                room_name = self._watched_channels[channel_id]
                sender = message.author.display_name
                content = message.content

                logger.info(f"Channel {room_name} from {sender}: {content}")

                if self.on_channel_message:
                    await self.on_channel_message(room_name, sender, content)

    async def on_presence_update(self, before: discord.Member, after: discord.Member):
        """Handle presence/status changes"""
        # Check if this is a friend
        if not self._is_friend(after):
            return

        username = after.name
        old_status = before.status
        new_status = after.status

        if old_status != new_status:
            logger.debug(f"Friend {username} status: {old_status} -> {new_status}")

            if new_status == DiscordStatus.offline:
                if self.on_friend_offline:
                    await self.on_friend_offline(username)
            elif old_status == DiscordStatus.offline:
                if self.on_friend_online:
                    ymsg_status = self._discord_to_ymsg_status(new_status)
                    await self.on_friend_online(username, ymsg_status)
            else:
                if self.on_friend_status_change:
                    ymsg_status = self._discord_to_ymsg_status(new_status)
                    await self.on_friend_status_change(username, ymsg_status)

    def _is_friend(self, user) -> bool:
        """Check if a user is in our friends list"""
        return any(f.id == user.id for f in self.friends)

    def _discord_to_ymsg_status(self, status: DiscordStatus) -> int:
        """Convert Discord status to YMSG status code"""
        mapping = {
            DiscordStatus.online: 0,      # Available
            DiscordStatus.idle: 999,      # Idle
            DiscordStatus.dnd: 2,         # Busy
            DiscordStatus.offline: -1,    # Offline (special)
            DiscordStatus.invisible: -1,  # Treat as offline
        }
        return mapping.get(status, 0)

    def _ymsg_to_discord_status(self, ymsg_status: int) -> DiscordStatus:
        """Convert YMSG status code to Discord status"""
        if ymsg_status == 0:
            return DiscordStatus.online
        elif ymsg_status == 2:
            return DiscordStatus.dnd
        elif ymsg_status in (999, 1, 3, 4, 5, 6, 7, 8, 9):
            return DiscordStatus.idle
        else:
            return DiscordStatus.online

    def get_friends_for_ymsg(self) -> Dict[str, List[str]]:
        """
        Get friends list formatted for YMSG buddy list.

        Returns dict of group_name -> list of usernames
        """
        # Group friends by status for now
        # Could be enhanced to use Discord friend nicknames or notes
        online = []
        away = []
        offline = []

        for friend in self.friends:
            name = friend.name
            if friend.status == DiscordStatus.offline:
                offline.append(name)
            elif friend.status in (DiscordStatus.idle, DiscordStatus.dnd):
                away.append(name)
            else:
                online.append(name)

        groups = {}
        if online:
            groups["Online"] = online
        if away:
            groups["Away"] = away
        if offline:
            groups["Offline"] = offline

        return groups

    def get_friend_statuses(self) -> Dict[str, int]:
        """Get all friend statuses as YMSG status codes"""
        statuses = {}
        for friend in self.friends:
            statuses[friend.name] = self._discord_to_ymsg_status(friend.status)
        return statuses

    async def send_dm(self, username: str, message: str) -> bool:
        """
        Send a DM to a Discord friend.

        Args:
            username: Discord username to send to
            message: Message content

        Returns:
            True if sent successfully
        """
        # Find the friend
        friend = None
        for f in self.friends:
            if f.name.lower() == username.lower():
                friend = f
                break

        if not friend:
            logger.warning(f"Friend not found: {username}")
            return False

        try:
            # Get or create DM channel
            if username not in self._dm_channels:
                self._dm_channels[username] = await friend.create_dm()

            channel = self._dm_channels[username]
            await channel.send(message)
            logger.info(f"Sent DM to {username}: {message}")
            return True

        except discord.Forbidden:
            logger.error(f"Cannot DM {username} - blocked or DMs disabled")
            return False
        except Exception as e:
            logger.error(f"Error sending DM to {username}: {e}")
            return False

    async def set_status(self, ymsg_status: int, custom_message: str = None):
        """Set our Discord status based on YMSG status"""
        discord_status = self._ymsg_to_discord_status(ymsg_status)

        try:
            if custom_message:
                activity = discord.CustomActivity(name=custom_message)
                await self.change_presence(status=discord_status, activity=activity)
            else:
                await self.change_presence(status=discord_status)
            logger.info(f"Set Discord status to {discord_status}")
        except Exception as e:
            logger.error(f"Error setting status: {e}")

    # Guild/Channel methods for chat rooms

    def get_guilds_and_channels(self) -> List[Dict]:
        """
        Get all accessible guilds and their text channels.
        Returns list of {guild_id, guild_name, channel_id, channel_name}
        """
        result = []
        for guild in self.guilds:
            for channel in guild.text_channels:
                # Check if we can read the channel
                perms = channel.permissions_for(guild.me)
                if perms.read_messages:
                    result.append({
                        'guild_id': guild.id,
                        'guild_name': guild.name,
                        'channel_id': channel.id,
                        'channel_name': channel.name
                    })
        return result

    def watch_channel(self, channel_id: int, room_name: str):
        """Register a channel to watch for messages"""
        self._watched_channels[channel_id] = room_name
        logger.info(f"Watching channel {channel_id} as room '{room_name}'")

    def unwatch_channel(self, channel_id: int):
        """Stop watching a channel"""
        self._watched_channels.pop(channel_id, None)

    async def send_channel_message(self, channel_id: int, message: str) -> bool:
        """Send a message to a Discord channel"""
        channel = self.get_channel(channel_id)
        if not channel:
            logger.warning(f"Channel not found: {channel_id}")
            return False

        try:
            await channel.send(message)
            logger.info(f"Sent to channel {channel_id}: {message}")
            return True
        except discord.Forbidden:
            logger.error(f"Cannot send to channel {channel_id} - no permission")
            return False
        except Exception as e:
            logger.error(f"Error sending to channel {channel_id}: {e}")
            return False

    def get_channel_by_room(self, room_name: str) -> Optional[int]:
        """Get channel ID for a room name"""
        for channel_id, name in self._watched_channels.items():
            if name == room_name:
                return channel_id
        return None


async def create_discord_client(token: str) -> DiscordBridge:
    """Create and connect a Discord client"""
    client = DiscordBridge()

    # Start in background
    asyncio.create_task(client.start(token))

    # Wait for ready
    while not client.is_ready():
        await asyncio.sleep(0.1)

    return client
