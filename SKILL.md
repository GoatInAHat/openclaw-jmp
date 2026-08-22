---
name: openclaw-jmp
description: Send and receive SMS through JMP.chat over XMPP with conservative trust routing, quarantine processing, and rate limits.
metadata: {"openclaw":{"emoji":"📱","homepage":"https://github.com/GoatInAHat/openclaw-jmp","requires":{"bins":["uv"]}}}
---

# OpenClaw JMP SMS

Send and receive SMS through a JMP.chat number and XMPP account.

## Safety boundary

SMS sender identity is not cryptographic proof. Caller IDs can be spoofed, so all inbound messages—including recognized owner numbers—are quarantined by default. The included anomaly checks are heuristics, not authentication.

Never expose the skill to a main agent with tools solely because a sender number matches. Direct owner routing exists only as an explicit unsafe compatibility opt-in via `JMP_ALLOW_UNAUTHENTICATED_OWNER_DIRECT=1`.

The quarantine path calls a model provider directly, gives it no local tools or workspace access, validates typed JSON, and fails closed. The OpenClaw CLI quarantine backend is disabled unless `JMP_ALLOW_OPENCLAW_CLI_QUARANTINE=1` is explicitly set after an operator reviews their sandbox policy.

## Setup

Create `~/.openclaw/openclaw-jmp/credentials.json` with mode `0600`:

```json
{
  "phone_number": "+15551234567",
  "jabber_id": "user@example.net",
  "password": "replace-me",
  "xmpp_server": "example.net",
  "sms_gateway": "cheogram.com"
}
```

Set `JMP_CREDENTIALS_PATH` to use a different file. Alternatively set `JMP_JABBER_ID`, `JMP_PASSWORD`, and optional `JMP_PHONE_NUMBER`, `JMP_XMPP_SERVER`, and `JMP_SMS_GATEWAY` in `skills.entries.openclaw-jmp.env`.

Optional configuration lives under `~/.openclaw/openclaw-jmp/`. Copy and customize the examples from `{baseDir}/config/` as needed:

- `verified_owners.example.json` → `verified_owners.json`
- `known_contacts.example.json` → `known_contacts.json`
- `blocked_numbers.example.json` → `blocked_numbers.json`
- `rate_limits.example.json` → `rate_limits.json`

Override `OPENCLAW_JMP_CONFIG_DIR`, `OPENCLAW_JMP_DATA_DIR`, or `OPENCLAW_JMP_AUDIT_DIR` for containers.

## Commands

Send:

```bash
uv run {baseDir}/scripts/send_sms.py "+15551234567" "Your message"
```

Listen for 60 seconds:

```bash
uv run {baseDir}/scripts/receive_sms.py --timeout 60
```

Run the daemon:

```bash
uv run {baseDir}/scripts/daemon.py
```

Inspect a routing decision:

```bash
uv run {baseDir}/scripts/routing_engine.py "+15551234567" "Test message"
```

Use E.164 phone numbers such as `+15551234567`.

## Quarantine provider

Inbound quarantine processing requires `ANTHROPIC_API_KEY` or `OPENAI_API_KEY`. Select models with `JMP_ANTHROPIC_MODEL` or `JMP_OPENAI_MODEL`. SMS content sent to quarantine is transmitted to the selected provider; do not process sensitive messages unless the provider and your data policy permit it.

## Runtime data

Credentials and user configuration stay outside the skill directory. Runtime logs default to `~/.openclaw/state/openclaw-jmp/`. Message history and audit logs contain phone numbers and message content; protect and rotate them accordingly.

See `{baseDir}/docs/ARCHITECTURE.md` for the design and threat model.
