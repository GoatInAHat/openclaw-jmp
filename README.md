# OpenClaw JMP SMS Skill

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Status: Beta](https://img.shields.io/badge/status-beta-orange.svg)](#release-status)

A **secure SMS channel skill** for [OpenClaw](https://github.com/openclaw) that enables AI agents to send and receive text messages via [JMP.chat](https://jmp.chat/)'s XMPP/Jabber bridge.

## 🔐 Security-First Design

This skill treats SMS as an **inherently untrusted medium**. Caller IDs are trivially spoofable, so recognized owner numbers are quarantined by default too. The anomaly checks are heuristics—not authentication.

- **Conservative owner routing** — Matching a configured owner number does not grant direct main-agent access by default
- **Quarantine Agent** — Messages from unverified numbers go through an isolated agent with NO tools, NO memory, and NO sensitive data access
- **Anti-Spoof Detection** — Behavioral analysis, carrier consistency checks, and timing pattern monitoring
- **Typed API Boundary** — External requests are translated into a strict typed schema, limiting what can be requested
- **Rate Limiting** — Per-number and global limits to prevent abuse

## ✨ Features

- 📱 Send and receive SMS via JMP.chat's XMPP bridge
- 🔒 Defense-in-depth security architecture
- 🤖 Isolated Quarantine Agent for untrusted messages
- 🎯 Behavioral anti-spoof detection
- 📊 Comprehensive audit logging
- ⚡ Async XMPP client (slixmpp)
- 🔑 Flexible credential management

## 📐 Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     EXTERNAL WORLD                          │
│                  (Untrusted Phone Numbers)                  │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    JMP/XMPP GATEWAY                         │
│  • Receives SMS via XMPP from cheogram.com                  │
│  • Normalizes to E.164 format                               │
│  • Extracts carrier metadata                                │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                   ROUTING DECISION                          │
│                                                             │
│   Is sender blocked?                                        │
│   ├── YES → DROP                                            │
│   └── NO  → QUARANTINE (default for every sender)          │
└─────────────────────────────────────────────────────────────┘
              │                              │
              ▼                              ▼
┌───────────────────────┐     ┌───────────────────────────────┐
│     MAIN AGENT        │     │      QUARANTINE AGENT         │
│                       │     │                               │
│  • Full tool access   │◄────│  • ZERO tools                 │
│  • Full memory        │     │  • Stateless                  │
│  • Trusted context    │     │  • No memory                  │
│                       │────►│  • JSON output only           │
│                       │     │  • Typed API boundary         │
└───────────────────────┘     └───────────────────────────────┘
```

### Trust Levels

| Level | Description | Route |
|-------|-------------|-------|
| `owner_verified` | Number recognized; heuristics passed | Quarantine by default |
| `owner_suspicious` | Owner number with spoof indicators | Quarantine |
| `known_contact` | Previously approved contact | Quarantine |
| `unknown` | Never seen before | Quarantine |
| `blocked` | Explicitly blocked | Dropped |

## 📦 Installation

### Prerequisites

- Python 3.10+
- [`uv`](https://docs.astral.sh/uv/) for isolated script dependencies
- A [JMP.chat](https://jmp.chat/) account (provides phone number + XMPP credentials)
- An XMPP server account (e.g., [Movim](https://movim.eu/))
- OpenClaw installed and configured

### Install as an OpenClaw skill

```bash
cd /path/to/your/openclaw/workspace/skills
git clone https://github.com/GoatInAHat/openclaw-jmp.git openclaw-jmp
```

For source development:

```bash
git clone https://github.com/GoatInAHat/openclaw-jmp.git
cd openclaw-jmp
python -m pip install -e ".[dev]"
```

## ⚙️ Configuration

### 1. Create credentials file

Create `~/.openclaw/openclaw-jmp/credentials.json` and restrict its permissions:

```bash
mkdir -p ~/.openclaw/openclaw-jmp
chmod 700 ~/.openclaw/openclaw-jmp
touch ~/.openclaw/openclaw-jmp/credentials.json
chmod 600 ~/.openclaw/openclaw-jmp/credentials.json
```

```json
{
  "phone_number": "+1XXXXXXXXXX",
  "jabber_id": "your-username@your-xmpp-server.com",
  "password": "your-xmpp-password",
  "xmpp_server": "your-xmpp-server.com",
  "sms_gateway": "cheogram.com"
}
```

> ⚠️ **Never commit this file.** Override its location with `JMP_CREDENTIALS_PATH`.

### 2. Set up owner verification

Copy and customize the example:

```bash
mkdir -p ~/.openclaw/openclaw-jmp
cp config/verified_owners.example.json ~/.openclaw/openclaw-jmp/verified_owners.json
```

Edit to add your phone number:

```json
{
  "owners": {
    "+1XXXXXXXXXX": {
      "name": "Your Name",
      "verified_at": "2026-01-01T00:00:00Z",
      "verified_via": "manual"
    }
  }
}
```

### 3. Configure rate limits (optional)

```bash
cp config/rate_limits.example.json ~/.openclaw/openclaw-jmp/rate_limits.json
```

## 🚀 Usage

### Send an SMS

```bash
uv run scripts/send_sms.py "+15551234567" "Hello from OpenClaw!"
```

### Start the daemon (listen for incoming)

```bash
uv run scripts/daemon.py
```

### Python API

```python
import asyncio
from scripts.jmp_client import send_sms_simple

# Send a message
asyncio.run(send_sms_simple("+1XXXXXXXXXX", "Hello!"))
```

### With OpenClaw

In your skill configuration, the agent can send SMS:

```bash
# From agent context
python /path/to/skills/jmp-sms/scripts/send_sms.py "+1XXXXXXXXXX" "Message text"
```

## 🛡️ Security Model

### The Quarantine Agent

By default, quarantine calls a configured model provider directly and exposes no local tools or workspace. Its response must pass the typed schema before the main agent sees it:

- **NO tool access** — Cannot execute commands, access files, or make API calls
- **NO memory** — Fresh session for each message, no state leakage
- **NO sensitive data** — Cannot see owner's calendar, files, or personal info
- **Typed output only** — Must output valid JSON matching strict schema

Even if an attacker sends a prompt-injection attempt via SMS, the default quarantine path:
1. Cannot take any actions
2. Cannot access local data
3. Can only output a limited set of request types

### Anti-Spoof Detection

The system monitors for spoofing indicators:

- **Carrier changes** — SIM swap detection
- **Timing anomalies** — Unusual hours, rapid-fire messages
- **Behavioral patterns** — Message style doesn't match history
- **Sensitive content** — Requests for passwords, credentials
- **Social engineering** — "Ignore previous instructions" patterns

### Typed API Boundary

External requests are constrained to these types:

```typescript
type MiddlemanRequest =
  | { type: 'get_public_info'; topic: string }
  | { type: 'check_availability'; dateRange: DateRange }
  | { type: 'request_callback'; topic: string; urgency: string }
  | { type: 'request_appointment'; preferredDate: string; purpose: string }
  | { type: 'leave_message'; message: string }
  | { type: 'relay_to_owner'; summary: string; category: string }
  | { type: 'request_verification'; purpose: string }
  | { type: 'cannot_process'; reason: string }
```

The Quarantine Agent **cannot request anything outside this schema**.

## 📁 Project Structure

```
openclaw-jmp/
├── scripts/
│   ├── jmp_client.py        # Core XMPP client
│   ├── send_sms.py          # Send messages
│   ├── routing_engine.py    # Trust routing logic
│   ├── anti_spoof.py        # Spoof detection
│   ├── quarantine_handler.py# Isolated agent handling
│   ├── api_schema.py        # Typed API definitions
│   ├── rate_limiter.py      # Rate limiting
│   ├── audit_logger.py      # Security logging
│   └── daemon.py            # Background listener
├── agents/
│   ├── quarantine_system.md # Quarantine agent prompt
│   └── main_sms_addendum.md # Main agent SMS rules
├── config/
│   ├── *.example.json       # Example configurations
│   └── rate_limits.json     # Rate limit settings
├── tests/
│   └── security/            # Security test suite
├── SKILL.md                 # OpenClaw skill definition
├── README.md                # This file
├── LICENSE                  # MIT License
└── pyproject.toml           # Package configuration
```

## 🧪 Testing

Run the test suite:

```bash
pytest tests/
```

Run security tests specifically:

```bash
pytest tests/security/
```

## 🔧 Development

### Install dev dependencies

```bash
pip install -e ".[dev]"
```

### Lint code

```bash
ruff check scripts/
ruff format scripts/
```

## Release status

This project is a **beta OpenClaw skill**, not a native gateway channel plugin. Outbound SMS and XMPP receipt are implemented. Main-agent/notification adapters remain deployment-specific; review the `TODO` markers before running the daemon unattended.

## 📚 Documentation

- [SKILL.md](SKILL.md) — OpenClaw skill documentation
- [Architecture Document](https://github.com/GoatInAHat/openclaw-jmp/blob/main/docs/ARCHITECTURE.md) — Full security architecture specification

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Security Issues

If you discover a security vulnerability, please **do not** open a public issue. Use the repository's [private security advisory form](https://github.com/GoatInAHat/openclaw-jmp/security/advisories/new).

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [JMP.chat](https://jmp.chat/) — SMS/voice bridging service
- [Cheogram](https://cheogram.com/) — XMPP-to-SMS gateway
- [slixmpp](https://slixmpp.readthedocs.io/) — Python XMPP library
- [OpenClaw](https://github.com/openclaw) — AI agent framework

---

**Built with 🔒 security in mind for the [OpenClaw](https://github.com/openclaw) ecosystem.**
