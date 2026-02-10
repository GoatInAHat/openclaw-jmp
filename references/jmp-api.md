# JMP.chat / Cheogram XMPP Protocol Reference

## Overview

JMP.chat provides phone numbers that route SMS/MMS through XMPP. The service uses:
- **Cheogram** as the SMS gateway
- Standard XMPP messaging for SMS send/receive
- SIP for voice calls (optional)

## Architecture

```
Your XMPP Client
      ↓
XMPP Server (movim.eu, etc.)
      ↓
cheogram.com (JMP gateway)
      ↓
Phone Network (SMS/MMS)
```

## JID Format

SMS contacts are addressed as:
```
+1XXXXXXXXXX@cheogram.com
```

Examples:
- `+13238776364@cheogram.com` - US number
- `+447700900123@cheogram.com` - UK number

## Sending SMS

Send a standard XMPP chat message to the phone JID:

```xml
<message type="chat" to="+13238776364@cheogram.com">
  <body>Hello from XMPP!</body>
</message>
```

## Receiving SMS

Incoming SMS arrives as XMPP messages from the phone JID:

```xml
<message from="+13238776364@cheogram.com" type="chat">
  <body>Reply from phone</body>
</message>
```

## MMS (Media Messages)

MMS content is delivered as:
1. **Small images**: Inline as XMPP file transfer
2. **Large media**: URLs in the message body

## Voice Calls

Voice calls use SIP through Cheogram. The SIP address format:
```
sip:+1XXXXXXXXXX@sip.cheogram.com
```

## Authentication

JMP uses your existing XMPP account. The Cheogram gateway is added as a 
contact/subscription to enable SMS routing.

## Supported XMPP Features

- XEP-0184: Message Delivery Receipts
- XEP-0085: Chat State Notifications
- XEP-0333: Chat Markers
- XEP-0363: HTTP File Upload (for MMS)

## Rate Limits

Standard carrier SMS limits apply:
- ~200 SMS/day per number (soft limit)
- Group SMS limited to ~10 recipients

## Resources

- JMP.chat: https://jmp.chat
- Cheogram: https://cheogram.com
- slixmpp: https://slixmpp.readthedocs.io/
- XMPP Standards: https://xmpp.org/extensions/
