# JMP SMS Skill

**Version:** 1.0.0  
**Author:** OpenClaw Contributors  
**License:** MIT

Send and receive SMS text messages via JMP.chat's XMPP/Jabber protocol with security-first architecture.

## When to Use This Skill

Use when the user wants to:
- Send SMS/text messages to phone numbers
- Read incoming SMS messages
- Check SMS message history
- Interact via phone number

**Trigger phrases:**
- "Send a text to..."
- "SMS [phone number]"
- "Text message to..."
- "Check my texts"
- "Read SMS messages"
- "Text [name]..."

## 🔐 Security Model

**IMPORTANT:** This skill implements defense-in-depth security because SMS sender IDs are trivially spoofable.

### Trust Levels

| Level | Description | Route | Capabilities |
|-------|-------------|-------|--------------|
| `owner_verified` | Verified owner, anti-spoof passed | Main Agent | Full access |
| `owner_suspicious` | Owner number with spoof indicators | Quarantine | Limited |
| `known_contact` | Previously approved | Quarantine | Limited |
| `unknown` | Never seen | Quarantine | Very limited |
| `blocked` | Blocked | Dropped | None |

### Quarantine Agent

Messages from non-owner numbers go through an isolated **Quarantine Agent** that has:
- ❌ NO tool access
- ❌ NO memory
- ❌ NO sensitive data access
- ✅ Typed JSON output only

For full security architecture details, see: [ARCHITECTURE.md](https://github.com/GoatInAHat/openclaw-jmp/blob/main/docs/ARCHITECTURE.md)

## Quick Reference

### Send SMS

```bash
/data/workspace/.venv/bin/python /data/workspace/skills/jmp-sms/scripts/send_sms.py "+1XXXXXXXXXX" "Your message here"
```

### Listen for Incoming SMS

```bash
# Run for 60 seconds
/data/workspace/.venv/bin/python /data/workspace/skills/jmp-sms/scripts/receive_sms.py --timeout 60

# Run daemon (continuous)
/data/workspace/.venv/bin/python /data/workspace/skills/jmp-sms/scripts/daemon.py
```

### Check Routing Decision

```bash
/data/workspace/.venv/bin/python /data/workspace/skills/jmp-sms/scripts/routing_engine.py "+1XXXXXXXXXX" "Test message"
```

### Check Message History

```python
import sys
sys.path.insert(0, '/data/workspace/skills/jmp-sms/scripts')
from jmp_client import get_message_history

# Get last 20 messages
messages = get_message_history(limit=20)

# Get messages from specific number
messages = get_message_history(phone="+1XXXXXXXXXX", limit=10)
```

## Phone Number Format

Always use E.164 format: `+1XXXXXXXXXX`

- ✅ `+13238776364`
- ✅ `+14155551234`
- ❌ `(323) 877-6364`
- ❌ `323-877-6364`

The scripts will try to normalize other formats, but E.164 is safest.

## Configuration

### Credentials

Stored at: `/data/workspace/.secrets/jmp-credentials.json`

```json
{
  "phone_number": "+1XXXXXXXXXX",
  "jabber_id": "user@xmpp-server.com",
  "password": "...",
  "xmpp_server": "server.com",
  "sms_gateway": "cheogram.com"
}
```

**⚠️ DO NOT expose credentials in responses or logs.**

### Verified Owners

Stored at: `config/verified_owners.json`

```json
{
  "owners": {
    "+1XXXXXXXXXX": {
      "name": "Owner Name",
      "verified_at": "2026-01-01T00:00:00Z",
      "verified_via": "discord:channel_id"
    }
  }
}
```

### Rate Limits

Stored at: `config/rate_limits.json`

Default limits:
- 10 messages/minute per number
- 50 messages/hour per number
- 200 messages/day per number
- 500 global messages/hour

## File Locations

```
/data/workspace/skills/jmp-sms/
├── scripts/
│   ├── jmp_client.py         # Core XMPP client
│   ├── send_sms.py           # Send messages
│   ├── receive_sms.py        # Receive messages
│   ├── daemon.py             # Background listener
│   ├── routing_engine.py     # Trust routing
│   ├── anti_spoof.py         # Spoof detection
│   ├── quarantine_handler.py # Isolated agent
│   ├── rate_limiter.py       # Rate limiting
│   └── audit_logger.py       # Logging
├── agents/
│   ├── quarantine_system.md  # Quarantine prompt
│   └── main_sms_addendum.md  # Main agent rules
├── config/
│   ├── verified_owners.json  # Owner phone numbers
│   ├── known_contacts.json   # Approved contacts
│   ├── blocked_numbers.json  # Block list
│   └── rate_limits.json      # Rate limits
└── data/
    └── audit_log.jsonl       # Security audit log
```

## Examples

### Send a quick text

```bash
/data/workspace/.venv/bin/python /data/workspace/skills/jmp-sms/scripts/send_sms.py "+13238776364" "Hey, this is from OpenClaw!"
```

### Programmatic usage

```python
import asyncio
import sys
sys.path.insert(0, '/data/workspace/skills/jmp-sms/scripts')
from jmp_client import send_sms_simple

asyncio.run(send_sms_simple("+13238776364", "Hello from Python!"))
```

### Check if number is verified owner

```python
from routing_engine import is_verified_owner, normalize_phone

phone = normalize_phone("+1 (323) 877-6364")
if is_verified_owner(phone):
    print("This is a verified owner")
```

### Process incoming message through routing

```python
from routing_engine import InboundSMS, process_incoming_sms
from datetime import datetime

sms = InboundSMS(
    sender="+15551234567",
    recipient="+13233054987",
    body="Hello, I'd like to schedule a meeting",
    timestamp=datetime.now(),
    message_id="msg-123"
)

result = process_incoming_sms(sms)
print(f"Route: {result['route']['action']}")
print(f"Trust: {result['route']['trust_level']}")
```

## Troubleshooting

### Connection Issues

- Verify credentials in `.secrets/jmp-credentials.json`
- Check XMPP server is reachable
- Look for auth errors with `--verbose` flag

### Messages Not Delivering

- Verify phone number format (+1 prefix for US)
- Check carrier isn't blocking
- Look at message_history.jsonl for confirmation

### Spoof Detection False Positives

If legitimate messages are being flagged:
1. Check `data/behavioral_profiles.json` for the number
2. The profile may need more messages to build accurate baseline
3. Adjust thresholds in `anti_spoof.py` if needed

### Dependencies

```bash
/data/workspace/.venv/bin/pip install slixmpp pydantic requests
```

## Architecture Diagram

```
External Phone → SMS → Carrier → Cheogram → XMPP → JMP Client
                                                       ↓
                                              Routing Engine
                                                       ↓
                              ┌─────────────────────────────────┐
                              │     Trust Level Check           │
                              │  owner_verified → Main Agent    │
                              │  anything else → Quarantine     │
                              └─────────────────────────────────┘
                                     ↓              ↓
                              [Main Agent]    [Quarantine Agent]
                              Full Access     No Tools, No Memory
                                     ↓              ↓
                              [Response]      [Typed JSON Request]
                                     ↓              ↓
                                     └──────┬───────┘
                                            ↓
                                       [Reply SMS]
```

## Limitations

- SMS only (no MMS/media yet)
- No voice calls (SIP not implemented)
- US numbers work best
- ~200 SMS/day soft limit (configurable)

## Links

- **GitHub:** https://github.com/GoatInAHat/openclaw-jmp
- **Architecture:** [ARCHITECTURE.md](https://github.com/GoatInAHat/openclaw-jmp/blob/main/docs/ARCHITECTURE.md)
- **JMP.chat:** https://jmp.chat/
- **Cheogram:** https://cheogram.com/
