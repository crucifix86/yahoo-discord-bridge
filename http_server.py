#!/usr/bin/env python3
"""
HTTP Server for Yahoo Chat Room Lists

Serves fake chat room categories/rooms to Yahoo Messenger clients.
Logs all requests to help understand the protocol.
"""

import http.server
import socketserver
import logging
import urllib.parse
import json
import os
import re


def strip_emojis(text):
    """Remove emojis and special Unicode characters, keep ASCII-friendly names"""
    if not text:
        return text
    # Remove emojis and other non-ASCII characters
    # Keep only letters, numbers, spaces, and basic punctuation
    cleaned = re.sub(r'[^\x00-\x7F]+', '', text)
    # Remove leading/trailing separators like ・ that got converted
    cleaned = cleaned.strip(' -_.')
    # Replace multiple spaces/dashes with single
    cleaned = re.sub(r'[-_\s]+', '-', cleaned)
    return cleaned if cleaned else 'general'

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/home/doug/yahoo-discord-bridge/http.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

PORT = 80

class YahooHTTPHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        logger.info(f"HTTP Request: {args[0]}")

    def do_GET(self):
        logger.info(f"=== GET request ===")
        logger.info(f"Path: {self.path}")
        logger.info(f"Headers: {dict(self.headers)}")

        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)

        logger.info(f"Parsed path: {parsed.path}")
        logger.info(f"Query params: {query}")

        # Check for chatroom_N parameters (room listing for category N)
        chatroom_key = None
        for key in query:
            if key.startswith('chatroom_'):
                chatroom_key = key
                break

        # Handle chat category request
        if 'chatcat' in query:
            self.send_chat_categories()
        elif chatroom_key:
            # Extract category ID from chatroom_N
            cat_id = chatroom_key.replace('chatroom_', '')
            self.send_category_rooms(cat_id)
        elif 'chatroom' in query or 'room' in query:
            room = query.get('room', query.get('chatroom', ['General']))[0]
            self.send_room_lobbies(room)
        elif parsed.path == '/ycontent/' or parsed.path == '/ycontent':
            self.send_chat_categories()
        elif parsed.path == '/capacity':
            # YM 9 capacity check - tells client where to connect for YMSG
            self.handle_capacity()
        else:
            # Return server list (for login) or empty response
            logger.info("Returning default server list response")
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            response = b"COLO_CAPACITY=1\nCS_IP_ADDRESS=192.168.1.121\nCS_PORT=5050\n"
            self.wfile.write(response)

    def send_chat_categories(self):
        """Send list of chat categories (Discord servers)"""
        # Try to load Discord guilds from JSON file
        guilds_file = os.path.join(os.path.dirname(__file__), 'discord_guilds.json')
        guilds = []

        if os.path.exists(guilds_file):
            try:
                with open(guilds_file, 'r') as f:
                    guilds = json.load(f)
                logger.info(f"Loaded {len(guilds)} Discord guilds from JSON")
            except Exception as e:
                logger.error(f"Error loading guilds JSON: {e}")

        # Build XML from Discord guilds
        xml_parts = ['<?xml version="1.0" encoding="utf-8"?>\n<content time="0">\n  <chatCategories>']

        if guilds:
            for cat_idx, guild in enumerate(guilds, start=1):
                guild_name = guild.get('name', 'Unknown').replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')
                xml_parts.append(f'\n    <category id="{cat_idx}" name="{guild_name}">')

                channels = guild.get('channels', [])
                for room_idx, channel in enumerate(channels[:20], start=1):  # Limit to 20 channels per server
                    # Strip emojis for Yahoo Messenger 5.x compatibility
                    raw_name = strip_emojis(channel.get('name', 'general'))
                    channel_name = raw_name.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')
                    channel_topic = (channel.get('topic', '') or '').replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')[:100]
                    room_id = f"{cat_idx}{room_idx:02d}"

                    xml_parts.append(f'''
      <room id="{room_id}" name="{channel_name}" topic="{channel_topic}" users="1" voices="0" webcams="0">
        <lobby id="1" name="{channel_name}:1" count="1" voices="0" webcams="0"/>
      </room>''')

                xml_parts.append('\n    </category>')
        else:
            # Fallback if no guilds loaded
            xml_parts.append('''
    <category id="1" name="Discord Servers">
      <room id="101" name="General" topic="Discord Bridge" users="1" voices="0" webcams="0">
        <lobby id="1" name="General:1" count="1" voices="0" webcams="0"/>
      </room>
    </category>''')

        xml_parts.append('\n  </chatCategories>\n</content>')
        xml = ''.join(xml_parts)

        logger.info(f"Sending chat categories XML ({len(guilds)} guilds)")
        self.send_response(200)
        self.send_header('Content-type', 'text/xml; charset=utf-8')
        self.send_header('Content-Length', str(len(xml.encode('utf-8'))))
        self.end_headers()
        self.wfile.write(xml.encode('utf-8'))

    def send_category_rooms(self, cat_id):
        """Send rooms for a specific category with chat server info"""
        guilds_file = os.path.join(os.path.dirname(__file__), 'discord_guilds.json')
        guilds = []

        if os.path.exists(guilds_file):
            try:
                with open(guilds_file, 'r') as f:
                    guilds = json.load(f)
            except Exception as e:
                logger.error(f"Error loading guilds JSON: {e}")

        # Get chat server IP from client's perspective (use the server they connected to)
        client_host = self.headers.get('Host', 'insider.msg.yahoo.com').split(':')[0]
        # Use 192.168.1.121 for local network
        chat_server_ip = "192.168.1.121"  # Your Linux server IP
        chat_server_port = "5050"  # YMSG port

        try:
            cat_idx = int(cat_id)
            if 1 <= cat_idx <= len(guilds):
                guild = guilds[cat_idx - 1]
                guild_name = guild.get('name', 'Unknown').replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')
                channels = guild.get('channels', [])

                xml_parts = [f'''<?xml version="1.0" encoding="utf-8"?>
<content time="0">
  <chatRooms category="{cat_idx}" name="{guild_name}">''']

                for room_idx, channel in enumerate(channels[:20], start=1):
                    # Strip emojis for Yahoo Messenger 5.x compatibility
                    raw_name = strip_emojis(channel.get('name', 'general'))
                    channel_name = raw_name.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')
                    channel_topic = (channel.get('topic', '') or '').replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')[:100]
                    room_id = f"{cat_idx}{room_idx:02d}"

                    # Include chat server info in each room
                    xml_parts.append(f'''
    <room id="{room_id}" name="{channel_name}" topic="{channel_topic}" users="1" voices="0" webcams="0">
      <lobby id="1" name="{channel_name}:1" count="1" voices="0" webcams="0" server="{chat_server_ip}" port="{chat_server_port}"/>
    </room>''')

                xml_parts.append('''
  </chatRooms>
</content>''')
                xml = ''.join(xml_parts)
            else:
                xml = f'''<?xml version="1.0" encoding="utf-8"?>
<content time="0">
  <chatRooms category="{cat_id}" name="Unknown">
    <room id="1" name="General" topic="Discord Bridge" users="1" voices="0" webcams="0">
      <lobby id="1" name="General:1" count="1" voices="0" webcams="0" server="{chat_server_ip}" port="{chat_server_port}"/>
    </room>
  </chatRooms>
</content>'''
        except ValueError:
            xml = f'''<?xml version="1.0" encoding="utf-8"?>
<content time="0">
  <chatRooms>
    <room id="1" name="General" topic="Discord Bridge" users="1" voices="0" webcams="0">
      <lobby id="1" name="General:1" count="1" voices="0" webcams="0" server="{chat_server_ip}" port="{chat_server_port}"/>
    </room>
  </chatRooms>
</content>'''

        logger.info(f"Sending category {cat_id} rooms with chat server {chat_server_ip}:{chat_server_port}")
        self.send_response(200)
        self.send_header('Content-type', 'text/xml; charset=utf-8')
        self.send_header('Content-Length', str(len(xml.encode('utf-8'))))
        self.end_headers()
        self.wfile.write(xml.encode('utf-8'))

    def send_room_lobbies(self, room_name):
        """Send lobbies for a specific room"""
        chat_server_ip = "192.168.1.121"  # Your Linux server IP
        chat_server_port = "5050"  # Chat server port
        xml = f'''<?xml version="1.0" encoding="utf-8"?>
<content time="0">
  <chatRooms>
    <room id="1" name="{room_name}" topic="Discord Room" users="5" voices="0" webcams="0">
      <lobby id="1" name="{room_name}:1" count="5" voices="0" webcams="0" server="{chat_server_ip}" port="{chat_server_port}"/>
    </room>
  </chatRooms>
</content>'''

        logger.info(f"Sending room lobbies for: {room_name}")
        self.send_response(200)
        self.send_header('Content-type', 'text/xml; charset=utf-8')
        self.send_header('Content-Length', str(len(xml.encode('utf-8'))))
        self.end_headers()
        self.wfile.write(xml.encode('utf-8'))

    def handle_capacity(self):
        """
        Handle YM 9 capacity check - this is the FIRST request YM 9 makes!

        YM 9 sends: GET http://vcs1.msg.yahoo.com/capacity
        Expected response format (TWO lines required!):
        COLO_CAPACITY=1
        CS_IP_ADDRESS=ip_address

        If COLO_CAPACITY=0, client won't connect to pager server!
        """
        logger.info("=== YM 9 CAPACITY CHECK ===")

        # Response format: TWO lines required!
        # COLO_CAPACITY must be non-zero or client won't connect
        response = "COLO_CAPACITY=1\nCS_IP_ADDRESS=192.168.1.121\n"

        logger.info(f"Returning capacity response: {response.strip()}")
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.send_header('Content-Length', str(len(response)))
        self.end_headers()
        self.wfile.write(response.encode())

def run_server():
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("0.0.0.0", PORT), YahooHTTPHandler) as httpd:
        logger.info(f"HTTP Server listening on 0.0.0.0:{PORT}")
        logger.info("Waiting for Yahoo Messenger chat requests...")
        httpd.serve_forever()

if __name__ == '__main__':
    run_server()
