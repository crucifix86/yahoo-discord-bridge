# Yahoo Messenger ↔ Discord Bridge

## Architecture

```
┌─────────────────┐      YMSG Protocol       ┌─────────────────┐      Discord API      ┌─────────────────┐
│  Yahoo Messenger │ ◄──── TCP:5050 ────►   │   Bridge Server  │ ◄──── HTTPS ────►    │     Discord      │
│  Client (old)    │                         │   (Python)       │                       │     Servers      │
└─────────────────┘                          └─────────────────┘                       └─────────────────┘
```

---

## Phase 1: Environment Setup

**Goal:** Get all pieces in place

- [ ] Download Yahoo Messenger 5.5 or 11 from OldVersion.com
- [ ] Install on Windows (or Wine)
- [ ] Edit registry `HKEY_CURRENT_USER\Software\Yahoo\Pager`:
  - Set `socket server` = `127.0.0.1`
  - Add `127.0.0.1` to start of `IPLookup`
- [ ] Set up Python 3.9+ environment
- [ ] Install discord.py-self: `pip install discord.py-self`
- [ ] Get Discord user token (from browser dev tools)

---

## Phase 2: Basic YMSG Server

**Goal:** YM client can connect and "log in"

### YMSG Packet Structure
```
Bytes 0-3:   "YMSG" (magic)
Bytes 4-7:   Version (we use 10)
Bytes 8-9:   Data length
Byte 11:     Service type
Byte 15:     Status
Bytes 16-19: Session ID
Bytes 20+:   Data (key��value��key��value��)
```

### Service Types to Implement
| Code | Name      | Description              |
|------|-----------|--------------------------|
| 76   | VERIFY    | Initial handshake        |
| 87   | AUTH      | Client sends username    |
| 84   | AUTHRESP  | Client sends credentials |
| 1    | LOGON     | Server confirms login    |
| 85   | LIST      | Buddy list data          |
| 18   | PING      | Keep-alive               |
| 2    | LOGOFF    | Disconnect               |

### Key Fields
| Key | Meaning           |
|-----|-------------------|
| 0   | Current user      |
| 1   | Username          |
| 4   | Message from      |
| 5   | Message to        |
| 7   | Friend username   |
| 10  | Status code       |
| 14  | Message content   |
| 87  | Friend groups     |
| 94  | Auth challenge    |

---

## Phase 3: Discord Connection

**Goal:** Connect to Discord as user, fetch data

```python
import discord
from discord.ext import commands

class DiscordBridge(discord.Client):
    async def on_ready(self):
        # Get friends list
        for friend in self.friends:
            print(f"{friend.name} - {friend.status}")

    async def on_message(self, message):
        # Handle incoming DMs
        if isinstance(message.channel, discord.DMChannel):
            # Forward to YMSG client
            pass
```

---

## Phase 4: Buddy List Bridge

**Goal:** Discord friends appear in YM buddy list

### Mapping
```
Discord Friend          →  YMSG Buddy
─────────────────────────────────────
friend.name             →  Field 7 (username)
friend.status.online    →  Status 0 (Available)
friend.status.idle      →  Status 999 (Idle)
friend.status.dnd       →  Status 2 (Busy)
friend.status.offline   →  Status (not in list)
friend.activity.name    →  Field 19 (custom status)
```

### YMSG Buddy List Format (Field 87)
```
GroupName:friend1,friend2,friend3\n
AnotherGroup:friend4,friend5\n
```

---

## Phase 5: Direct Messages

**Goal:** Send/receive DMs through YM client

### YM → Discord
1. YM client sends Service 6 (MESSAGE)
2. Extract Field 5 (recipient) and Field 14 (message)
3. Find Discord user matching recipient
4. Send via `user.send(message)`

### Discord → YM
1. Receive `on_message` event for DM
2. Build YMSG packet with Service 6
3. Set Field 4 (from), Field 5 (to), Field 14 (message)
4. Send to YM client connection

---

## Phase 6: Chat Rooms

**Goal:** Discord channels appear as YM chat rooms

### Mapping Options
```
Option A: Server = Room Category, Channel = Room
Option B: Each Channel = Separate Room
Option C: Configurable mapping
```

### YMSG Chat Services
| Code | Name       | Description          |
|------|------------|----------------------|
| 150  | CHATJOIN   | Join a room          |
| 151  | CHATLEAVE  | Leave a room         |
| 152  | CHATMSG    | Message in room      |
| 155  | CHATPM     | PM from room         |

---

## Phase 7: Status & Presence

**Goal:** Status syncs both ways

### YM → Discord
| YMSG Status | Discord Status |
|-------------|----------------|
| 0 (Avail)   | online         |
| 1-9 (Away)  | idle           |
| 2 (Busy)    | dnd            |
| 999 (Idle)  | idle           |

### Discord → YM
When Discord presence changes:
1. Build YMSG Service 4 (ISBACK) or Service 5 (ISAWAY)
2. Send to all connected YM sessions

---

## Phase 8: Polish

**Goal:** Make it feel native

- [ ] Typing indicators (Service 75 NOTIFY)
- [ ] Smiley translation (YM codes ↔ Discord emoji)
- [ ] File transfer (complex - maybe skip)
- [ ] Reconnection handling
- [ ] Multiple YM client support
- [ ] Avatar/profile pictures
- [ ] Message history on login

---

## Phase 9: User-Friendly Installer

**Goal:** One-click setup for average users

### Components
- [ ] PyInstaller standalone .exe (no Python install needed)
- [ ] Bundled Yahoo Messenger client (optional download)
- [ ] Simple GUI for first-time setup:
  - Discord token input (with instructions)
  - Auto registry configuration
  - Start/Stop bridge button
  - System tray icon
- [ ] NSIS or Inno Setup installer wizard

### Installer Flow
```
1. Welcome screen
2. "Enter your Discord token" (with help link)
3. "Install Yahoo Messenger?" (checkbox, downloads if needed)
4. "Configure registry automatically?" (checkbox)
5. Install files to Program Files
6. Create Start Menu shortcut
7. Launch bridge on startup (optional)
8. Done!
```

### GUI Config Tool (tkinter or PyQt)
```
┌─────────────────────────────────────┐
│  Yahoo-Discord Bridge         [─][×]│
├─────────────────────────────────────┤
│                                     │
│  Discord Token: [••••••••••••]  [?] │
│                                     │
│  Status: ● Connected                │
│                                     │
│  [Start Bridge]  [Stop]  [Settings] │
│                                     │
│  ☑ Start with Windows               │
│  ☑ Minimize to system tray          │
│                                     │
└─────────────────────────────────────┘
```

### Build Commands
```bash
# Create standalone exe
pyinstaller --onefile --windowed --icon=yahoo.ico bridge_gui.py

# Or with Nuitka for better performance
nuitka --standalone --onefile --windows-icon=yahoo.ico bridge_gui.py
```

---

## File Structure

```
yahoo-discord-bridge/
├── bridge.py           # Main entry point (CLI)
├── bridge_gui.py       # GUI launcher with tkinter
├── ymsg/
│   ├── __init__.py
│   ├── server.py       # TCP server for YMSG
│   ├── protocol.py     # Packet encode/decode
│   └── services.py     # Service handlers
├── discord_client/
│   ├── __init__.py
│   └── client.py       # Discord connection
├── mapping/
│   ├── __init__.py
│   ├── buddies.py      # Friend list mapping
│   ├── messages.py     # Message translation
│   └── status.py       # Presence mapping
├── installer/
│   ├── setup.iss       # Inno Setup script
│   ├── yahoo.ico       # App icon
│   └── bundle/         # Bundled YM client
├── config.py           # Settings
├── config.json         # User config (token, prefs)
└── users.json          # Local user data
```

---

## References

- Ayyhoo server: `./ayyhoo/server.go`
- VB6 client source: `./uy-messenger/`
- YMSG v9 spec: https://libyahoo2.sourceforge.net/ymsg-9.txt
- discord.py-self: https://github.com/dolfies/discord.py-self
