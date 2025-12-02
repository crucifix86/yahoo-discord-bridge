# Yahoo-Discord Bridge

A bridge that allows classic Yahoo Messenger clients (5.x/6.x) to send and receive Discord DMs. This implements a YMSG protocol server that translates between Yahoo Messenger and Discord.

## Features

- **Bidirectional Messaging**: Send messages from Yahoo Messenger to Discord and receive Discord DMs in Yahoo Messenger
- **Friend List Sync**: Discord friends appear as Yahoo Messenger buddies
- **Presence Updates**: See when Discord friends come online/offline
- **Native Linux Server**: Runs headless on Linux, no GUI required
- **Remote Access**: Can be accessed from other machines on the network (Windows, etc.)

## Requirements

- Python 3.10+
- Linux server (tested on Debian/Ubuntu)
- Yahoo Messenger 5.x or 6.x client
- Discord account with user token

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/yahoo-discord-bridge.git
   cd yahoo-discord-bridge
   ```

2. Create virtual environment and install dependencies:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install discord.py-self
   ```

3. Create `config.json` with your Discord token:
   ```json
   {
     "discord_token": "YOUR_DISCORD_USER_TOKEN"
   }
   ```

## Configuration

### Server Setup (Linux)

The bridge listens on port 5050 for YMSG connections. To run:

```bash
source venv/bin/activate
python bridge_native.py
```

Or use the restart script:
```bash
./restart_bridge.sh
```

### Client Setup (Yahoo Messenger)

You need to redirect Yahoo Messenger's connection attempts to your bridge server.

#### Local Machine (Linux with Wine)
Edit `~/.wine/drive_c/windows/system32/drivers/etc/hosts`:
```
127.0.0.1 scs.msg.yahoo.com
127.0.0.1 scsa.msg.yahoo.com
127.0.0.1 scsb.msg.yahoo.com
127.0.0.1 scsc.msg.yahoo.com
127.0.0.1 relay.msg.yahoo.com
127.0.0.1 cs.msg.yahoo.com
```

#### Remote Windows Machine
Run the provided batch file as Administrator, or manually add to `C:\Windows\System32\drivers\etc\hosts`:
```
192.168.1.121 scs.msg.yahoo.com
192.168.1.121 scsa.msg.yahoo.com
192.168.1.121 scsb.msg.yahoo.com
192.168.1.121 scsc.msg.yahoo.com
192.168.1.121 relay.msg.yahoo.com
192.168.1.121 cs.msg.yahoo.com
192.168.1.121 login.yahoo.com
192.168.1.121 insider.msg.yahoo.com
192.168.1.121 vcs1.msg.yahoo.com
192.168.1.121 vcs2.msg.yahoo.com
```

Replace `192.168.1.121` with your Linux server's IP address.

## Project Structure

```
yahoo-discord-bridge/
├── bridge_native.py      # Main bridge (YMSG server + Discord client)
├── ymsg/
│   ├── protocol.py       # YMSG packet encoding/decoding
│   └── server_threaded.py # Threaded YMSG server implementation
├── mapping/
│   └── smileys.py        # Yahoo/Discord emoji conversion
├── discord_client/       # Discord client utilities
├── config.json           # Configuration file (create this)
├── restart_bridge.sh     # Helper script to restart the bridge
└── README.md
```

## YMSG Protocol Notes

This implementation supports YMSG version 10 (Yahoo Messenger 5.x) and version 16 (Yahoo Messenger 9.x).

### Key Protocol Details

- **Port**: 5050 (TCP)
- **Packet Structure**: 20-byte header + key-value data separated by `0xC0 0x80`
- **Services Used**:
  - `VERIFY (76)`: Initial handshake
  - `AUTH (87)`: Authentication request
  - `AUTHRESP (84)`: Authentication response
  - `LOGON (1)`: Login confirmation
  - `LIST (85)`: Buddy list
  - `MESSAGE (6)`: Instant messages
  - `ISBACK (4)`: Friend online status
  - `LOGOFF (2)`: Logout/friend offline

### Message Packet Format

For **outgoing** messages (client to server):
- Key `1`: Sender (logged-in user)
- Key `5`: Recipient
- Key `14`: Message text

For **incoming** messages (server to client):
- Key `4`: Sender (remote user)
- Key `5`: Recipient (logged-in user)
- Key `14`: Message text

## Troubleshooting

### Messages not displaying
- Ensure incoming messages use key `4` for sender (not key `1`)
- Use `status=1` and the actual `session_id`

### Connection refused
- Check that the bridge is running: `ss -tlnp | grep 5050`
- Verify hosts file redirects are correct
- Ensure firewall allows port 5050

### Discord not connecting
- Verify your Discord token is valid
- Check `bridge.log` for errors

## License

MIT License

## Acknowledgments

- YMSG protocol documentation from various reverse-engineering efforts
- discord.py-self library for Discord user account access
