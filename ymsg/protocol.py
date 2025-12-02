"""
YMSG Protocol Implementation

Packet structure:
- Bytes 0-3:   "YMSG" magic
- Bytes 4-7:   Version (big-endian, we use 10)
- Bytes 8-9:   Data length (big-endian)
- Bytes 10-11: Service type (big-endian)
- Bytes 12-15: Status (big-endian)
- Bytes 16-19: Session ID (big-endian)
- Bytes 20+:   Data (key<sep>value<sep>key<sep>value<sep>...)

Separator: 0xC0 0x80
"""

import struct
from typing import Dict, List, Optional, Tuple

YMSG_MAGIC = b'YMSG'
YMSG_HEADER_SIZE = 20
YMSG_SEPARATOR = b'\xc0\x80'
YMSG_VERSION = 10  # YM 9 uses version 10


class YMSGPacket:
    """Represents a YMSG protocol packet"""

    def __init__(self, service: int = 0, status: int = 0,
                 session_id: int = 0, data: Dict[str, str] = None):
        self.version = YMSG_VERSION
        self.service = service
        self.status = status
        self.session_id = session_id
        self.data = data or {}

    def __repr__(self):
        return (f"YMSGPacket(service={self.service}, status={self.status}, "
                f"session={self.session_id}, data={self.data})")


def encode_data(data: Dict[str, str]) -> bytes:
    """Encode key-value pairs into YMSG data format"""
    result = b''
    for key, value in data.items():
        result += str(key).encode('utf-8') + YMSG_SEPARATOR
        result += str(value).encode('utf-8') + YMSG_SEPARATOR
    return result


def encode_data_list(items: List[str]) -> bytes:
    """Encode a list of alternating keys/values into YMSG data format"""
    result = b''
    for item in items:
        result += str(item).encode('utf-8') + YMSG_SEPARATOR
    return result


def decode_data(data: bytes) -> Dict[str, str]:
    """Decode YMSG data format into key-value pairs"""
    result = {}
    parts = data.split(YMSG_SEPARATOR)
    # Remove empty trailing element
    parts = [p for p in parts if p]

    for i in range(0, len(parts) - 1, 2):
        try:
            key = parts[i].decode('utf-8', errors='replace')
            value = parts[i + 1].decode('utf-8', errors='replace')
            result[key] = value
        except (IndexError, UnicodeDecodeError):
            continue

    return result


def encode_packet(packet: YMSGPacket) -> bytes:
    """Encode a YMSGPacket into bytes for transmission"""
    data_bytes = encode_data(packet.data)
    data_len = len(data_bytes)

    # Build header (20 bytes)
    header = bytearray(YMSG_HEADER_SIZE)

    # Magic "YMSG"
    header[0:4] = YMSG_MAGIC

    # Version (bytes 4-5, big-endian)
    header[4] = (packet.version >> 8) & 0xFF
    header[5] = packet.version & 0xFF

    # Vendor ID (bytes 6-7) - use 0
    header[6] = 0
    header[7] = 0

    # Data length (bytes 8-9, big-endian)
    header[8] = (data_len >> 8) & 0xFF
    header[9] = data_len & 0xFF

    # Service type (bytes 10-11, big-endian)
    header[10] = (packet.service >> 8) & 0xFF
    header[11] = packet.service & 0xFF

    # Status (bytes 12-15, big-endian)
    header[12] = (packet.status >> 24) & 0xFF
    header[13] = (packet.status >> 16) & 0xFF
    header[14] = (packet.status >> 8) & 0xFF
    header[15] = packet.status & 0xFF

    # Session ID (bytes 16-19, big-endian)
    header[16] = (packet.session_id >> 24) & 0xFF
    header[17] = (packet.session_id >> 16) & 0xFF
    header[18] = (packet.session_id >> 8) & 0xFF
    header[19] = packet.session_id & 0xFF

    return bytes(header) + data_bytes


def decode_packet(raw: bytes) -> Optional[YMSGPacket]:
    """Decode raw bytes into a YMSGPacket"""
    if len(raw) < YMSG_HEADER_SIZE:
        return None

    # Check magic
    if raw[0:4] != YMSG_MAGIC:
        return None

    packet = YMSGPacket()

    # Version (bytes 4-5, big-endian)
    packet.version = (raw[4] << 8) | raw[5]

    # Data length (bytes 8-9, big-endian)
    data_len = (raw[8] << 8) | raw[9]

    # Service type (bytes 10-11, big-endian)
    packet.service = (raw[10] << 8) | raw[11]

    # Status (bytes 12-15, big-endian)
    packet.status = (raw[12] << 24) | (raw[13] << 16) | (raw[14] << 8) | raw[15]

    # Session ID
    packet.session_id = (raw[16] << 24) | (raw[17] << 16) | (raw[18] << 8) | raw[19]

    # Data
    if data_len > 0 and len(raw) >= YMSG_HEADER_SIZE + data_len:
        data_bytes = raw[YMSG_HEADER_SIZE:YMSG_HEADER_SIZE + data_len]
        packet.data = decode_data(data_bytes)

    return packet


def read_packet_from_stream(reader) -> Tuple[Optional[YMSGPacket], bytes]:
    """
    Async helper to read a complete packet from a stream reader.
    Returns (packet, raw_bytes) tuple.
    """
    # This is a sync signature but will be used with async
    pass


# Service type constants (for reference)
class Service:
    LOGON = 1
    LOGOFF = 2
    ISAWAY = 3
    ISBACK = 4
    MESSAGE = 6
    IDACT = 7
    IDDEACT = 8
    PING = 18
    AUTHRESP = 84
    LIST = 85
    AUTH = 87
    ADDBUDDY = 131
    REMBUDDY = 132
    NOTIFY = 75
    VERIFY = 76
    CHATJOIN = 150
    CHATLEAVE = 151
    CHATMSG = 152


# Status constants
class Status:
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
    INVISIBLE = 12
    CUSTOM = 99
    IDLE = 999
    OFFLINE = 0x5a55aa56
