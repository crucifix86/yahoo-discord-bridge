# Yahoo-Discord Bridge Implementation Plan

## Goal
Support both Yahoo Messenger 5.x AND Yahoo Messenger 9 for chat rooms bridged to Discord.

## Current Status (Updated 2025-12-03 - Session 2)
- **YM 5.x Login**: Working
- **YM 5.x Buddy List**: Working
- **YM 5.x Chat Room List**: Working (via HTTP server)
- **YM 5.x Chat Room Join**: NOT WORKING (CHATJOIN response not accepted)
- **YM 9 Login**: WORKING!
- **YM 9 Buddy List**: WORKING! (shows all Discord friends)
- **YM 9 Status Updates**: WORKING! (structured STATUS_15 format)
- **YM 9 Keepalive**: Improved (5 min timeout, PING handling added)

---

## Phase 1: Yahoo Messenger 9 Login Support - COMPLETED!

### 1.1 HTTPS Auth Server - DONE
YM 9 does web-based auth BEFORE connecting to YMSG server.

**Auth Flow (Working):**
1. Client connects to YMSG server on port 5050
2. Client sends AUTH (0x57) with just username
3. Server replies with challenge string (field 94) + `key 13=2` for web auth
4. Client fetches `https://login.yahoo.com/config/pwtoken_get?login=USER&passwd=PASS&chal=CHALLENGE`
5. Server returns: `0\r\nymsgr=TOKEN\r\n`
6. Client fetches `https://login.yahoo.com/config/pwtoken_login?token=TOKEN`
7. Server returns: `0\r\ncrumb=CRUMB\r\nY=Y_COOKIE\r\nT=T_COOKIE\r\ncookievalidfor=86400\r\n`
8. Client sends AUTHRESP (0x54) with Y/T cookies (keys 277, 278, 307)
9. Server sends LIST_15 (241), LOGON (1), STATUS_15 (240) packets

**Completed Tasks:**
- [x] Add login.yahoo.com to hosts file (points to 192.168.1.121)
- [x] Create HTTPS server on port 443 (https_auth_server.py)
- [x] Handle /config/pwtoken_get - returns fake token
- [x] Handle /config/pwtoken_login - returns Y/T cookies + crumb
- [x] Generate self-signed SSL cert with SANs for all Yahoo domains
- [x] Import cert into Windows trusted root store

### 1.2 v16 Auth Response - DONE
- [x] Detect client version from YMSG header (v10 vs v16)
- [x] For v16: Send AUTH challenge with `key 13=2` (triggers web auth)
- [x] Handle token-based authentication fields (277=T cookie, 278=Y cookie, 307=crumb)
- [x] Maintain v10 auth for YM 5.x backward compatibility

### 1.3 v16 Login Packets - PARTIALLY WORKING
- [x] Must use LIST_15 (service 241) - regular LIST (85) breaks login!
- [x] LOGON (service 1) works
- [x] STATUS_15 (service 240) for buddy status updates
- [ ] Buddy list format for LIST_15 needs work - buddies don't show in client

**Client shows after login:**
- Colo Capacity: 1
- CS IP Address: 192.168.1.121
- CS Port: 5050

---

## Phase 1.5: YM 9 Buddy List - COMPLETED!

### Solution
LIST_15 requires structured entries with duplicate keys. Added `data_list` support to protocol.

### LIST_15 Format (Working)
```
[302][318][300][318][65][GroupName]     <- Start group
[302][319][300][319][7][buddy1]         <- First buddy
[301][319][300][319][7][buddy2]         <- Subsequent buddies
[301][319][303][319]                    <- End buddies in group
[301][318][303][318]                    <- End group/list
```

### STATUS_15 Format (Working)
```
[302][315][300][315]                    <- Start status entry
[7][username]                           <- Buddy name
[10][status]                            <- Status code (0=online)
[13][1]                                 <- Flag
[241][0]                                <- Protocol type
[244][6]                                <- Unknown field
[301][315][303][315]                    <- End status entry
```

### Tasks Completed
- [x] Implement proper LIST_15 packet format with structured buddy entries
- [x] Added encode_data_list() support for duplicate keys
- [x] STATUS_15 with structured format shows online friends

---

## Phase 1.6: YM 9 Keepalive - KNOWN LIMITATION

### Current Behavior
- YM9 disconnects after ~60 seconds of idle time
- Client automatically reconnects ~20 seconds after disconnect
- This appears to be application-level behavior, not fixable from server side

### Attempted Solutions (None Worked)
- PING (service 18) with 143=60, 144=1 - no effect
- KEEPALIVE (service 138) - sent at various intervals, doesn't prevent timeout
- Various timing intervals - 10s, 15s, 20s, 30s, 45s, 50s - none helped
- Responding to SKINNAME (service 21) telemetry packets
- Responding to Y7_CHAT_SESSION (service 212) packets
- TCP socket keepalive at OS level

### Technical Notes from OpenYMSG Research
- According to OpenYMSG source code:
  - CLIENT sends KEEPALIVE (138) to SERVER every 60 seconds
  - SERVER sends PING (18) with 143="60", 144="1" after login
  - Client considers login complete after receiving LIST_15 with status=0
- YM9 client is NOT sending us KEEPALIVE packets - instead it disconnects
- This suggests client isn't starting its keepalive timer after login
- The 60-second timeout matches OpenYMSG's KEEPALIVE_TIMEOUT_IN_SECS constant
- Client reconnects automatically (~20s after disconnect), so functionally it works
- Further investigation would require reverse-engineering the YM9 client binary

### Workaround
- Accept the 60-second reconnect cycle
- Messages work, buddy list works, statuses work
- User just sees periodic disconnect/reconnect

---

## Phase 2: Yahoo Messenger 9 Chat Rooms

### 2.1 Research YM 9 Chat Protocol
- YM 9 chat may use different service codes or fields
- May require HTTPS for chat room list (vs HTTP for YM 5.x)
- Lobby system may differ

### 2.2 Implement YM 9 Chat Join
- [ ] Capture YM 9 CHATJOIN packets to see exact format
- [ ] Implement v16-compatible CHATJOIN response
- [ ] Test chat room window opens

### 2.3 Implement Chat Messaging
- [ ] Handle CHATMSG (service 168/0xa8) for v16
- [ ] Forward messages to Discord channels
- [ ] Forward Discord messages back to YM chat

---

## Phase 3: Maintain YM 5.x Compatibility

### 3.1 Version Detection - DONE
- [x] Detect protocol version from packet header
- [x] Route to appropriate handler based on version

### 3.2 Dual Protocol Support
- [x] Keep v10 handlers for YM 5.x
- [x] Add v16 handlers for YM 9
- [ ] Shared Discord integration layer

---

## Technical Notes

### Protocol Versions
| Version | Client | Auth Method |
|---------|--------|-------------|
| v10 | YM 5.x | Simple challenge-response |
| v16 | YM 9 | Web token (pwtoken_get/login) |

### Key Service Codes
| Service | Code | Description | Version |
|---------|------|-------------|---------|
| LOGON | 1 | Login confirmation | Both |
| ISBACK | 4 | Buddy online status | v10 |
| PING | 18 (0x12) | Keep alive | Both |
| AUTH | 87 (0x57) | Authentication | Both |
| AUTHRESP | 84 (0x54) | Auth response | Both |
| LIST | 85 (0x55) | Buddy list | v10 |
| CHATJOIN | 152 (0x98) | Join chat room | Both |
| CHATMSG | 168 (0xa8) | Chat message | Both |
| STATUS_15 | 240 (0xf0) | Buddy status | v16 |
| LIST_15 | 241 (0xf1) | Buddy list | v16 |

### Key Field Numbers
| Field | Description |
|-------|-------------|
| 0, 1 | Username |
| 3 | Current user |
| 7 | Buddy screen name |
| 10 | Status code |
| 13 | Auth method (2=web auth) |
| 59 | Cookie B (marks packet complete) |
| 65 | Group name (LIST_15) |
| 87 | Buddy list string (LIST) |
| 94 | Challenge string |
| 277 | T cookie |
| 278 | Y cookie |
| 300, 301, 302 | LIST_15 structure markers |
| 307 | Crumb |

### Windows Hosts Entries Needed
Point to your server IP (e.g., 192.168.1.121):
```
192.168.1.121 scs.msg.yahoo.com
192.168.1.121 scsa.msg.yahoo.com
192.168.1.121 scsb.msg.yahoo.com
192.168.1.121 scsc.msg.yahoo.com
192.168.1.121 login.yahoo.com
192.168.1.121 vcs1.msg.yahoo.com
192.168.1.121 vcs2.msg.yahoo.com
192.168.1.121 cs.yahoo.com
192.168.1.121 insider.msg.yahoo.com
```

### Server Components
| Component | Port | Purpose |
|-----------|------|---------|
| bridge_native.py | 5050 | Main YMSG server |
| bridge_native.py | 5101 | Chat server |
| http_server.py | 80 | Chat room list (YM 5.x) |
| https_auth_server.py | 443 | HTTPS auth (YM 9) |

---

## Next Steps
1. Fix LIST_15 format to show buddies in YM 9
2. Implement PING/keepalive handling
3. Test 1:1 messaging in YM 9
4. Move to chat room support
