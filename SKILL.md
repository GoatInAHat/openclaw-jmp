# JMP SMS Skill

Send and receive SMS text messages via JMP.chat's XMPP/Jabber protocol.

## When to Use This Skill

Use when the user wants to:
- Send SMS/text messages to phone numbers
- Read incoming SMS messages
- Check SMS message history
- Interact via phone number (+13233054987)

**Trigger phrases:**
- "Send a text to..."
- "SMS [phone number]"
- "Text message to..."
- "Check my texts"
- "Read SMS messages"

## Quick Reference

### Send SMS
```bash
/data/workspace/.venv/bin/python /data/workspace/skills/jmp-sms/scripts/send_sms.py "+1XXXXXXXXXX" "Your message here"
```

### Listen for Incoming SMS
```bash
# Run for 60 seconds
/data/workspace/.venv/bin/python /data/workspace/skills/jmp-sms/scripts/receive_sms.py --timeout 60

# Run until one message received
/data/workspace/.venv/bin/python /data/workspace/skills/jmp-sms/scripts/receive_sms.py --once
```

### Check Message History
```python
from jmp_client import get_message_history

# Get last 20 messages
messages = get_message_history(limit=20)

# Get messages from specific number
messages = get_message_history(phone="+13238776364", limit=10)
```

## Phone Number Format

Always use E.164 format: `+1XXXXXXXXXX`
- ✓ `+13238776364`
- ✓ `+14155551234`
- ✗ `(323) 877-6364`
- ✗ `323-877-6364`

The scripts will try to normalize other formats, but E.164 is safest.

## Configuration

Credentials stored at: `/data/workspace/.secrets/jmp-credentials.json`

```json
{
  "phone_number": "+13233054987",
  "jabber_id": "user@xmpp-server.com",
  "password": "...",
  "xmpp_server": "server.com",
  "sms_gateway": "cheogram.com"
}
```

**DO NOT expose credentials in responses or logs.**

## Message History

Messages are logged to: `/data/workspace/skills/jmp-sms/message_history.jsonl`

Format (JSONL):
```json
{"direction": "outgoing", "phone": "+13238776364", "body": "Hello!", "timestamp": "2026-02-10T22:30:00"}
{"direction": "incoming", "phone": "+13238776364", "body": "Hi back!", "timestamp": "2026-02-10T22:31:00"}
```

## Examples

### Send a quick text
```bash
/data/workspace/.venv/bin/python /data/workspace/skills/jmp-sms/scripts/send_sms.py "+13238776364" "Hey, this is Berry from OpenClaw!"
```

### Programmatic usage
```python
import asyncio
import sys
sys.path.insert(0, '/data/workspace/skills/jmp-sms/scripts')
from jmp_client import send_sms_simple

asyncio.run(send_sms_simple("+13238776364", "Hello from Python!"))
```

## Troubleshooting

### Connection Issues
- Verify credentials in `/data/workspace/.secrets/jmp-credentials.json`
- Check XMPP server is reachable
- Look for auth errors in verbose mode: `--verbose`

### Messages Not Delivering
- Verify phone number format (+1 prefix for US)
- Check carrier isn't blocking (try different number)
- Look at message_history.jsonl for send confirmation

### Dependencies
Ensure virtual environment has slixmpp:
```bash
/data/workspace/.venv/bin/pip install slixmpp
```

## Architecture

```
OpenClaw Agent
     ↓
send_sms.py / receive_sms.py
     ↓
jmp_client.py (slixmpp)
     ↓
XMPP Server (movim.eu)
     ↓
Cheogram Gateway
     ↓
Phone Network (SMS)
```

## Limitations

- SMS only (no MMS/media yet)
- No voice calls (SIP not implemented)
- US numbers work best
- ~200 SMS/day soft limit

## Future Enhancements

- [ ] MMS support (image/media messages)
- [ ] Voice calls via SIP
- [ ] Group SMS
- [ ] Delivery receipts
- [ ] Contact management
