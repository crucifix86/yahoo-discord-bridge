# Yahoo-Discord Bridge Configuration

import json
import os

CONFIG_FILE = os.path.join(os.path.dirname(__file__), 'config.json')

# YMSG Server Settings
YMSG_HOST = '127.0.0.1'
YMSG_PORT = 5050
YMSG_PROTOCOL_VERSION = 10

# YMSG Service Types
class YMSGService:
    LOGON = 1
    LOGOFF = 2
    ISAWAY = 3
    ISBACK = 4
    MESSAGE = 6
    PING = 18
    NOTIFY = 75  # Typing
    VERIFY = 76  # Handshake
    AUTHRESP = 84
    LIST = 85
    AUTH = 87
    CHATJOIN = 150
    CHATLEAVE = 151
    CHATMSG = 152

# YMSG Status Codes
class YMSGStatus:
    AVAILABLE = 0
    BRB = 1
    BUSY = 2
    NOT_AT_HOME = 3
    NOT_AT_DESK = 4
    NOT_IN_OFFICE = 5
    ON_PHONE = 6
    ON_VACATION = 7
    OUT_TO_LUNCH = 8
    STEPPED_OUT = 9
    CUSTOM = 99
    IDLE = 999

# YMSG Key Fields
class YMSGKey:
    CURRENT_USER = '0'
    USERNAME = '1'
    FROM = '4'
    TO = '5'
    FRIEND = '7'
    NUM_ONLINE = '8'
    STATUS = '10'
    MESSAGE = '14'
    CUSTOM_STATUS = '19'
    FRIEND_GROUPS = '87'
    IGNORE_LIST = '88'
    ALIASES = '89'
    CHALLENGE = '94'

# Separator bytes for YMSG data
YMSG_SEPARATOR = b'\xc0\x80'


def load_config():
    """Load user configuration from config.json"""
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    return {
        'discord_token': '',
        'start_with_windows': False,
        'minimize_to_tray': True
    }


def save_config(config):
    """Save user configuration to config.json"""
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=2)
