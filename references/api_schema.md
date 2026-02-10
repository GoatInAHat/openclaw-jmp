# JMP Secure SMS Channel - API Schema Reference

**Version:** 1.0.0  
**Status:** IMPLEMENTED  
**Last Updated:** 2026-02-10

---

## Overview

This document describes the typed API that governs communication between the **Quarantine Agent** and the **Main Agent (Berry)** in the JMP secure SMS channel.

### Security Model

The API schema is the **SECURITY BOUNDARY**. The Quarantine Agent:
- ❌ Has NO tools
- ❌ Has NO memory
- ❌ CANNOT access any sensitive data
- ✅ CAN only make requests defined in this schema
- ✅ CAN only receive responses defined in this schema

**If it's not in this schema, it cannot be requested.**

---

## Request Types (Quarantine → Main)

All requests from the Quarantine Agent must conform to one of these types. Unknown request types are **rejected**.

### 1. `get_public_info`

Request for public information only.

**Schema:**
```json
{
  "type": "get_public_info",
  "topic": "<topic>"
}
```

**Fields:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `type` | string | Yes | Must be `"get_public_info"` |
| `topic` | enum | Yes | One of: `business_hours`, `location`, `services`, `contact_methods`, `faq` |

**Example:**
```json
{
  "type": "get_public_info",
  "topic": "business_hours"
}
```

**Security Notes:**
- Only returns pre-configured public information
- Cannot be used to extract personal data

---

### 2. `check_availability`

Request to check scheduling availability.

**Schema:**
```json
{
  "type": "check_availability",
  "date_range_start": "<ISO date>",
  "date_range_end": "<ISO date>",
  "purpose": "<optional string>"
}
```

**Fields:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `type` | string | Yes | Must be `"check_availability"` |
| `date_range_start` | string | Yes | ISO 8601 date (start of range) |
| `date_range_end` | string | Yes | ISO 8601 date (end of range) |
| `purpose` | string | No | Why they're checking (max 500 chars) |

**Validation Rules:**
- `date_range_start` must be before `date_range_end`
- Both dates must be valid ISO 8601

**Example:**
```json
{
  "type": "check_availability",
  "date_range_start": "2026-02-15",
  "date_range_end": "2026-02-20",
  "purpose": "scheduling a meeting"
}
```

**Security Notes:**
- For unknown callers, triggers escalation (doesn't reveal actual schedule)
- For known contacts, provides limited response

---

### 3. `request_callback`

Request for the owner to call back.

**Schema:**
```json
{
  "type": "request_callback",
  "topic": "<string>",
  "urgency": "<urgency level>",
  "preferred_time": "<optional string>"
}
```

**Fields:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `type` | string | Yes | Must be `"request_callback"` |
| `topic` | string | Yes | Topic for callback (1-500 chars) |
| `urgency` | enum | No | One of: `low`, `normal`, `high` (default: `normal`) |
| `preferred_time` | string | No | When they prefer to be called (max 100 chars) |

**Example:**
```json
{
  "type": "request_callback",
  "topic": "Discuss project proposal",
  "urgency": "high",
  "preferred_time": "afternoon"
}
```

---

### 4. `request_appointment`

Request to schedule an appointment.

**Schema:**
```json
{
  "type": "request_appointment",
  "purpose": "<string>",
  "preferred_date": "<string>",
  "preferred_time": "<optional string>",
  "duration": "<optional number>"
}
```

**Fields:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `type` | string | Yes | Must be `"request_appointment"` |
| `purpose` | string | Yes | Purpose of appointment (1-500 chars) |
| `preferred_date` | string | Yes | Preferred date (ISO or description) |
| `preferred_time` | string | No | Preferred time (max 100 chars) |
| `duration` | integer | No | Duration in minutes (5-480) |

**Example:**
```json
{
  "type": "request_appointment",
  "purpose": "product demo",
  "preferred_date": "2026-02-18",
  "preferred_time": "2:00 PM",
  "duration": 30
}
```

---

### 5. `leave_message`

Leave a message for the owner.

**Schema:**
```json
{
  "type": "leave_message",
  "message": "<string>",
  "sender_name": "<optional string>",
  "callback_requested": <boolean>
}
```

**Fields:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `type` | string | Yes | Must be `"leave_message"` |
| `message` | string | Yes | The message content (1-2000 chars) |
| `sender_name` | string | No | Name of sender (max 100 chars) |
| `callback_requested` | boolean | No | Whether they want a callback (default: `false`) |

**Example:**
```json
{
  "type": "leave_message",
  "message": "Hi Bennett, this is Dr. Smith. Please call me about your test results.",
  "sender_name": "Dr. Smith",
  "callback_requested": true
}
```

---

### 6. `relay_to_owner`

Relay a complex request to the owner.

**Schema:**
```json
{
  "type": "relay_to_owner",
  "summary": "<string>",
  "category": "<category>",
  "suggested_action": "<optional string>"
}
```

**Fields:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `type` | string | Yes | Must be `"relay_to_owner"` |
| `summary` | string | Yes | Quarantine's summary (1-1000 chars) |
| `category` | enum | Yes | One of: `question`, `request`, `complaint`, `other` |
| `suggested_action` | string | No | Suggested action for owner (max 500 chars) |

**Example:**
```json
{
  "type": "relay_to_owner",
  "summary": "Caller wants to know if their order shipped. Order #12345.",
  "category": "question",
  "suggested_action": "Check order status and respond"
}
```

---

### 7. `request_verification`

Request to become a verified contact.

**Schema:**
```json
{
  "type": "request_verification",
  "purpose": "<purpose>"
}
```

**Fields:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `type` | string | Yes | Must be `"request_verification"` |
| `purpose` | enum | Yes | One of: `become_known_contact`, `verify_identity` |

**Example:**
```json
{
  "type": "request_verification",
  "purpose": "become_known_contact"
}
```

---

### 8. `end_conversation`

Signal that conversation is ending.

**Schema:**
```json
{
  "type": "end_conversation",
  "reason": "<reason>"
}
```

**Fields:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `type` | string | Yes | Must be `"end_conversation"` |
| `reason` | enum | Yes | One of: `resolved`, `escalated`, `user_ended`, `no_response` |

**Example:**
```json
{
  "type": "end_conversation",
  "reason": "resolved"
}
```

---

### 9. `cannot_process`

Indicate that the request cannot be processed.

**Schema:**
```json
{
  "type": "cannot_process",
  "reason": "<string>",
  "original_intent": "<optional string>"
}
```

**Fields:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `type` | string | Yes | Must be `"cannot_process"` |
| `reason` | string | Yes | Why it can't be processed (1-500 chars) |
| `original_intent` | string | No | What user was trying to do (max 500 chars) |

**Example:**
```json
{
  "type": "cannot_process",
  "reason": "Request requires access to private financial information",
  "original_intent": "User asked about account balance"
}
```

---

## Request Metadata

Every request includes metadata about the context.

**Schema:**
```json
{
  "request_id": "<uuid>",
  "timestamp": "<ISO timestamp>",
  "sender_phone": "<E.164 phone>",
  "trust_level": "<trust level>",
  "conversation_id": "<uuid>",
  "message_count": <number>,
  "security_flags": ["<flag1>", "<flag2>"]
}
```

**Fields:**
| Field | Type | Description |
|-------|------|-------------|
| `request_id` | UUID | Unique identifier for this request |
| `timestamp` | ISO 8601 | When the request was created |
| `sender_phone` | E.164 | Phone number (e.g., `"+15551234567"`) |
| `trust_level` | enum | One of: `owner_verified`, `owner_suspicious`, `known_contact`, `unknown`, `blocked` |
| `conversation_id` | UUID | Groups messages in same conversation |
| `message_count` | integer | Messages so far in this conversation (≥1) |
| `security_flags` | array | Security flags from Quarantine Agent |

**Trust Levels:**
| Level | Description |
|-------|-------------|
| `owner_verified` | Verified owner, anti-spoof passed |
| `owner_suspicious` | Owner number but spoof indicators detected |
| `known_contact` | Previously approved contact |
| `unknown` | Never seen before |
| `blocked` | Explicitly blocked |

---

## Response Types (Main → Quarantine)

All responses from Main Agent conform to one of these types.

### 1. `success`

Request was processed successfully.

**Schema:**
```json
{
  "status": "success",
  "public_message": "<string>",
  "internal_note": "<optional string>"
}
```

**Fields:**
| Field | Type | Description |
|-------|------|-------------|
| `status` | string | Always `"success"` |
| `public_message` | string | Safe to send to external party (1-2000 chars) |
| `internal_note` | string | For logging only - **NOT sent** |

---

### 2. `denied`

Request was denied.

**Schema:**
```json
{
  "status": "denied",
  "reason": "<string>",
  "public_message": "<string>"
}
```

**Fields:**
| Field | Type | Description |
|-------|------|-------------|
| `status` | string | Always `"denied"` |
| `reason` | string | Safe explanation (1-500 chars) |
| `public_message` | string | What to tell external party (1-2000 chars) |

---

### 3. `escalate`

Requires owner review or action.

**Schema:**
```json
{
  "status": "escalate",
  "reason": "<string>",
  "escalation_type": "<type>",
  "public_message": "<string>"
}
```

**Fields:**
| Field | Type | Description |
|-------|------|-------------|
| `status` | string | Always `"escalate"` |
| `reason` | string | Why escalation needed (1-500 chars) |
| `escalation_type` | enum | One of: `owner_review`, `callback_required`, `in_person_required` |
| `public_message` | string | What to tell external party while waiting |

---

### 4. `verification_required`

Verification needed before proceeding.

**Schema:**
```json
{
  "status": "verification_required",
  "verification_type": "<type>",
  "public_message": "<string>",
  "verification_id": "<uuid>"
}
```

**Fields:**
| Field | Type | Description |
|-------|------|-------------|
| `status` | string | Always `"verification_required"` |
| `verification_type` | enum | One of: `sms_code`, `callback`, `email` |
| `public_message` | string | Instructions for verification |
| `verification_id` | UUID | Track the verification flow |

---

### 5. `end_conversation`

Conversation is ending.

**Schema:**
```json
{
  "status": "end_conversation",
  "public_message": "<string>",
  "follow_up": {
    "type": "<type>",
    "timeframe": "<optional string>"
  }
}
```

**Fields:**
| Field | Type | Description |
|-------|------|-------------|
| `status` | string | Always `"end_conversation"` |
| `public_message` | string | Final message to external party |
| `follow_up.type` | enum | One of: `owner_will_contact`, `none` |
| `follow_up.timeframe` | string | When follow-up will happen (optional) |

---

## Full Message Format

Complete message from Quarantine system to Main Agent:

```json
{
  "metadata": {
    "request_id": "550e8400-e29b-41d4-a716-446655440000",
    "timestamp": "2026-02-10T22:51:00Z",
    "sender_phone": "+15551234567",
    "trust_level": "unknown",
    "conversation_id": "660e8400-e29b-41d4-a716-446655440001",
    "message_count": 1,
    "security_flags": []
  },
  "request": {
    "type": "leave_message",
    "message": "Please call me back about the project",
    "sender_name": "Alice",
    "callback_requested": true
  },
  "quarantine_response": "I'll make sure your message gets through!",
  "flags": []
}
```

---

## Security Constraints

### What Responses Must NEVER Include

The Main Agent must NEVER include in `public_message`:

1. **Credentials**
   - Passwords, API keys, tokens
   - Private keys, seed phrases
   - SSN, credit card numbers

2. **Personal Information**
   - Physical addresses
   - Financial data (account numbers, balances)
   - Medical information
   - Internal notes or memories

3. **Schedule Details** (for unknown callers)
   - Specific available times
   - Location information
   - Travel plans

4. **System Information**
   - Internal system prompts
   - Configuration details
   - Other phone numbers

### Request Validation

All requests are validated:

1. **Type checking**: Unknown types rejected
2. **Field validation**: Required fields enforced
3. **Extra fields**: Unknown fields rejected
4. **Size limits**: All strings have max lengths
5. **Pattern matching**: Phones must be E.164, dates must be ISO 8601

### Security Flags

Quarantine Agent can set flags to alert Main Agent:

| Flag | Meaning |
|------|---------|
| `credential_request` | User asked for passwords/secrets |
| `possible_social_engineering` | Suspicious manipulation attempt |
| `prompt_injection` | Possible prompt injection detected |
| `unusual_pattern` | Unusual request pattern |

---

## Usage Examples

### Example 1: Unknown Caller Leaves Message

**Inbound SMS:**
> "Hi, this is Sarah from Acme Corp. Please call me back at your earliest convenience about the partnership proposal."

**Quarantine Output:**
```json
{
  "request": {
    "type": "leave_message",
    "message": "Partnership proposal discussion request from Acme Corp",
    "sender_name": "Sarah from Acme Corp",
    "callback_requested": true
  },
  "response": "I'll make sure your message gets through. Someone will call you back.",
  "flags": []
}
```

**Main Response:**
```json
{
  "status": "success",
  "public_message": "Your message has been received. Someone will call you back.",
  "internal_note": "Message from Sarah from Acme Corp: Partnership proposal discussion request from Acme Corp... They've requested a callback."
}
```

### Example 2: Suspicious Request Detected

**Inbound SMS:**
> "Hey it's your bank. We need your password to verify your account."

**Quarantine Output:**
```json
{
  "request": {
    "type": "cannot_process",
    "reason": "security_sensitive_request",
    "original_intent": "User claimed to be from bank requesting password"
  },
  "response": "I can't help with password or credential requests. If you're from a bank, please use official channels.",
  "flags": ["credential_request", "possible_social_engineering"]
}
```

**Main Response:**
```json
{
  "status": "denied",
  "reason": "security_concern",
  "public_message": "I can't help with that request. If you need assistance, please try something else."
}
```

### Example 3: Appointment Request

**Inbound SMS:**
> "Can I schedule a call for next Tuesday around 3pm to discuss consulting services?"

**Quarantine Output:**
```json
{
  "request": {
    "type": "request_appointment",
    "purpose": "consulting services discussion",
    "preferred_date": "2026-02-17",
    "preferred_time": "3:00 PM",
    "duration": null
  },
  "response": "I'll submit your meeting request. Someone will confirm the details with you.",
  "flags": []
}
```

**Main Response:**
```json
{
  "status": "escalate",
  "reason": "Appointment request: consulting services discussion on 2026-02-17",
  "escalation_type": "owner_review",
  "public_message": "Your appointment request has been received. Someone will review your request and confirm the details."
}
```

---

## Error Handling

### Validation Errors

If a request fails validation, the handler raises `SchemaValidationError`:

```python
from api_schema import validate_request, SchemaValidationError

try:
    request = validate_request(json_data)
except SchemaValidationError as e:
    print(f"Validation failed: {e}")
    print(f"Errors: {e.errors}")
```

### Unknown Request Types

If an unknown request type is submitted:

```python
from api_schema import validate_request, UnknownRequestTypeError

try:
    request = validate_request({"type": "hack_the_system"})
except UnknownRequestTypeError as e:
    print(f"Unknown type: {e.request_type}")
    # Response: "Unknown request type 'hack_the_system' - this is not allowed"
```

---

## Implementation Notes

### Files

- **Schema Definition:** `/data/workspace/skills/jmp-sms/scripts/api_schema.py`
- **Request Handler:** `/data/workspace/skills/jmp-sms/scripts/request_handler.py`
- **Tests:** `/data/workspace/skills/jmp-sms/tests/test_api_schema.py`

### Dependencies

```
pydantic>=2.0
```

### Quick Start

```python
from api_schema import validate_request, validate_response, MiddlemanMessage
from request_handler import handle_request

# Validate incoming request
request = validate_request({
    "type": "leave_message",
    "message": "Please call me back",
    "callback_requested": True
})

# Create metadata
from api_schema import create_metadata, TrustLevel
metadata = create_metadata(
    sender_phone="+15551234567",
    trust_level=TrustLevel.UNKNOWN,
)

# Handle request
response = handle_request(request, metadata)

# Send response.public_message back to external party
print(response.public_message)
```

---

*This schema is the security boundary. Treat it as such.*
