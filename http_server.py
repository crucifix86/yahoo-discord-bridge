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

        # Handle chat category request
        if 'chatcat' in query or 'chatcat' in self.path:
            self.send_chat_categories()
        elif 'chatroom' in query or 'room' in query:
            room = query.get('room', query.get('chatroom', ['General']))[0]
            self.send_room_lobbies(room)
        elif parsed.path == '/ycontent/' or parsed.path == '/ycontent':
            self.send_chat_categories()
        else:
            # Return server list (for login) or empty response
            logger.info("Returning default server list response")
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            response = b"COLO_CAPACITY=1\nCS_IP_ADDRESS=127.0.0.1\nCS_PORT=5050\n"
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
                    channel_name = channel.get('name', 'general').replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')
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

    def send_room_lobbies(self, room_name):
        """Send lobbies for a specific room"""
        xml = f'''<?xml version="1.0" encoding="utf-8"?>
<content time="0">
  <chatRooms>
    <room id="1" name="{room_name}" topic="Discord Room" users="5" voices="0" webcams="0">
      <lobby id="1" name="{room_name}:1" count="5" voices="0" webcams="0"/>
    </room>
  </chatRooms>
</content>'''

        logger.info(f"Sending room lobbies for: {room_name}")
        self.send_response(200)
        self.send_header('Content-type', 'text/xml; charset=utf-8')
        self.send_header('Content-Length', str(len(xml.encode('utf-8'))))
        self.end_headers()
        self.wfile.write(xml.encode('utf-8'))

def run_server():
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("0.0.0.0", PORT), YahooHTTPHandler) as httpd:
        logger.info(f"HTTP Server listening on 0.0.0.0:{PORT}")
        logger.info("Waiting for Yahoo Messenger chat requests...")
        httpd.serve_forever()

if __name__ == '__main__':
    run_server()
