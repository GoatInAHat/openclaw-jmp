#!/usr/bin/env python3
"""
Routing Decision Engine for JMP Secure SMS Channel.

Determines trust level for incoming messages and routes them
appropriately to Main Agent or Quarantine Agent.
"""

import json
import logging
import os
import threading
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

try:
    from .anti_spoof import AntiSpoofResult, run_anti_spoof_checks
except ImportError:  # Direct script execution
    from anti_spoof import AntiSpoofResult, run_anti_spoof_checks

# Paths
try:
    from .paths import CONFIG_DIR, DATA_DIR
except ImportError:  # Direct script execution
    from paths import CONFIG_DIR, DATA_DIR
VERIFIED_OWNERS_PATH = CONFIG_DIR / "verified_owners.json"
KNOWN_CONTACTS_PATH = CONFIG_DIR / "known_contacts.json"
BLOCKED_NUMBERS_PATH = CONFIG_DIR / "blocked_numbers.json"
AUDIT_LOG_PATH = DATA_DIR / "audit_log.jsonl"

logger = logging.getLogger(__name__)

# Thread safety for config file access
_config_lock = threading.RLock()


class TrustLevel(str, Enum):
    """Trust levels for incoming messages."""

    OWNER_VERIFIED = "owner_verified"  # Verified owner, anti-spoof passed
    OWNER_SUSPICIOUS = "owner_suspicious"  # Owner number but spoof indicators
    KNOWN_CONTACT = "known_contact"  # Previously approved, not owner
    UNKNOWN = "unknown"  # Never seen before
    BLOCKED = "blocked"  # Explicitly blocked


class RouteAction(str, Enum):
    """Routing actions for messages."""

    MAIN_AGENT = "main_agent"  # Route to main agent (Main Agent)
    QUARANTINE_AGENT = "quarantine"  # Route to quarantine agent
    DROP = "drop"  # Silently drop message
    CHALLENGE = "challenge"  # Send verification challenge


@dataclass
class InboundSMS:
    """Normalized incoming SMS message."""

    sender: str  # E.164 format: "+15551234567"
    recipient: str  # Our JMP number
    body: str  # Raw message text
    timestamp: datetime
    message_id: str
    media: list[dict] = field(default_factory=list)  # MMS attachments
    carrier_info: dict | None = None
    voice_attestation: dict | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "sender": self.sender,
            "recipient": self.recipient,
            "body": self.body,
            "timestamp": self.timestamp.isoformat(),
            "message_id": self.message_id,
            "media": self.media,
            "carrier_info": self.carrier_info,
            "voice_attestation": self.voice_attestation,
        }


@dataclass
class RouteDecision:
    """Result of routing decision."""

    action: RouteAction
    trust_level: TrustLevel
    reason: str
    spoof_result: AntiSpoofResult | None = None
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "action": self.action.value,
            "trust_level": self.trust_level.value,
            "reason": self.reason,
            "spoof_result": self.spoof_result.to_dict() if self.spoof_result else None,
            "warnings": self.warnings,
        }


class ConfigManager:
    """Thread-safe configuration file manager."""

    def __init__(self):
        self._cache: dict[Path, tuple[float, Any]] = {}
        self._cache_ttl = 5.0  # Reload config every 5 seconds max

    def _load_json(self, path: Path, default: Any = None) -> Any:
        """Load JSON file with caching."""
        with _config_lock:
            now = datetime.now().timestamp()

            # Check cache
            if path in self._cache:
                cached_time, cached_data = self._cache[path]
                if now - cached_time < self._cache_ttl:
                    return cached_data

            # Load from disk
            if not path.exists():
                return default if default is not None else {}

            try:
                with open(path) as f:
                    data = json.load(f)
                    self._cache[path] = (now, data)
                    return data
            except (json.JSONDecodeError, OSError) as e:
                logger.error(f"Error loading {path}: {e}")
                return default if default is not None else {}

    def _save_json(self, path: Path, data: Any) -> bool:
        """Save JSON file atomically."""
        with _config_lock:
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                temp_path = path.with_suffix(".tmp")
                with open(temp_path, "w") as f:
                    json.dump(data, f, indent=2, default=str)
                temp_path.rename(path)
                # Invalidate cache
                self._cache.pop(path, None)
                return True
            except OSError as e:
                logger.error(f"Error saving {path}: {e}")
                return False

    def invalidate_cache(self, path: Path | None = None) -> None:
        """Invalidate cached config."""
        with _config_lock:
            if path:
                self._cache.pop(path, None)
            else:
                self._cache.clear()


# Global config manager
_config = ConfigManager()


def normalize_phone(phone: str) -> str:
    """
    Normalize phone number to E.164 format.

    Args:
        phone: Phone number in various formats

    Returns:
        E.164 formatted number (e.g., "+15551234567")
    """
    # Strip non-digits except +
    cleaned = "".join(c for c in phone if c.isdigit() or c == "+")

    # Handle various formats
    if cleaned.startswith("+"):
        return cleaned
    elif len(cleaned) == 10:
        return "+1" + cleaned
    elif len(cleaned) == 11 and cleaned.startswith("1"):
        return "+" + cleaned
    else:
        return "+" + cleaned


def get_verified_owners() -> dict[str, dict]:
    """
    Get verified owner numbers and their metadata.

    Returns:
        Dict mapping phone numbers to owner metadata
    """
    data = _config._load_json(VERIFIED_OWNERS_PATH, {"owners": {}})
    return data.get("owners", {})


def get_known_contacts() -> dict[str, dict]:
    """
    Get known contact numbers and their metadata.

    Returns:
        Dict mapping phone numbers to contact metadata
    """
    data = _config._load_json(KNOWN_CONTACTS_PATH, {"contacts": {}})
    return data.get("contacts", {})


def get_blocked_numbers() -> set[str]:
    """
    Get blocked phone numbers.

    Returns:
        Set of blocked phone numbers
    """
    data = _config._load_json(BLOCKED_NUMBERS_PATH, {"blocked": []})
    return set(data.get("blocked", []))


def is_verified_owner(phone: str) -> bool:
    """Check if phone number is a verified owner."""
    normalized = normalize_phone(phone)
    owners = get_verified_owners()
    return normalized in owners


def is_known_contact(phone: str) -> bool:
    """Check if phone number is a known contact."""
    normalized = normalize_phone(phone)
    contacts = get_known_contacts()
    return normalized in contacts


def is_blocked(phone: str) -> bool:
    """Check if phone number is blocked."""
    normalized = normalize_phone(phone)
    blocked = get_blocked_numbers()
    return normalized in blocked


def get_owner_metadata(phone: str) -> dict | None:
    """Get metadata for a verified owner."""
    normalized = normalize_phone(phone)
    owners = get_verified_owners()
    return owners.get(normalized)


def add_verified_owner(
    phone: str, verified_via: str, carrier: str | None = None, name: str | None = None
) -> bool:
    """
    Add a verified owner.

    Args:
        phone: Phone number to verify
        verified_via: Channel used for verification (e.g., "discord:channel_id")
        carrier: Known carrier at time of verification
        name: Optional display name

    Returns:
        True if added successfully
    """
    normalized = normalize_phone(phone)
    data = _config._load_json(VERIFIED_OWNERS_PATH, {"owners": {}})

    data["owners"][normalized] = {
        "phone": normalized,
        "name": name,
        "verified_at": datetime.now().isoformat(),
        "verified_via": verified_via,
        "carrier_at_verification": carrier,
        "trust_level": TrustLevel.OWNER_VERIFIED.value,
    }

    return _config._save_json(VERIFIED_OWNERS_PATH, data)


def add_known_contact(
    phone: str, name: str | None = None, approved_by: str | None = None, notes: str | None = None
) -> bool:
    """
    Add a known contact.

    Args:
        phone: Phone number to add
        name: Contact name
        approved_by: How this contact was approved
        notes: Optional notes about the contact

    Returns:
        True if added successfully
    """
    normalized = normalize_phone(phone)
    data = _config._load_json(KNOWN_CONTACTS_PATH, {"contacts": {}})

    data["contacts"][normalized] = {
        "phone": normalized,
        "name": name,
        "approved_at": datetime.now().isoformat(),
        "approved_by": approved_by,
        "notes": notes,
    }

    return _config._save_json(KNOWN_CONTACTS_PATH, data)


def add_blocked_number(phone: str, reason: str | None = None) -> bool:
    """
    Block a phone number.

    Args:
        phone: Phone number to block
        reason: Optional reason for blocking

    Returns:
        True if added successfully
    """
    normalized = normalize_phone(phone)
    data = _config._load_json(BLOCKED_NUMBERS_PATH, {"blocked": [], "metadata": {}})

    if normalized not in data["blocked"]:
        data["blocked"].append(normalized)

    if reason:
        data.setdefault("metadata", {})[normalized] = {
            "blocked_at": datetime.now().isoformat(),
            "reason": reason,
        }

    return _config._save_json(BLOCKED_NUMBERS_PATH, data)


def remove_blocked_number(phone: str) -> bool:
    """Remove a phone number from the block list."""
    normalized = normalize_phone(phone)
    data = _config._load_json(BLOCKED_NUMBERS_PATH, {"blocked": [], "metadata": {}})

    if normalized in data["blocked"]:
        data["blocked"].remove(normalized)
        data.get("metadata", {}).pop(normalized, None)
        return _config._save_json(BLOCKED_NUMBERS_PATH, data)

    return True


def log_audit_event(
    event_type: str,
    sender: str | None = None,
    trust_level: TrustLevel | None = None,
    details: dict | None = None,
) -> None:
    """
    Log an audit event.

    Args:
        event_type: Type of event (e.g., 'routing_decision', 'spoof_detected')
        sender: Phone number involved
        trust_level: Assigned trust level
        details: Additional event details
    """
    try:
        AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

        event = {
            "timestamp": datetime.now().isoformat(),
            "event": event_type,
            "sender": sender,
            "trust_level": trust_level.value if trust_level else None,
            "details": details or {},
        }

        with open(AUDIT_LOG_PATH, "a") as f:
            f.write(json.dumps(event) + "\n")

    except OSError as e:
        logger.error(f"Failed to write audit log: {e}")


def route_message(sms: InboundSMS) -> RouteDecision:
    """
    Determine routing for an incoming SMS message.

    This is the core routing decision function that:
    1. Checks if sender is blocked
    2. Checks if sender is a verified owner (with anti-spoof)
    3. Checks if sender is a known contact
    4. Routes unknown numbers to quarantine

    Args:
        sms: Normalized incoming SMS

    Returns:
        RouteDecision with action and trust level
    """
    sender = normalize_phone(sms.sender)

    # 1. Check if blocked
    if is_blocked(sender):
        logger.info(f"Dropping message from blocked number: {sender}")
        log_audit_event(
            "blocked_message",
            sender,
            TrustLevel.BLOCKED,
            {
                "action": "drop",
            },
        )
        return RouteDecision(
            action=RouteAction.DROP,
            trust_level=TrustLevel.BLOCKED,
            reason="Number is blocked",
        )

    # 2. Check if verified owner
    if is_verified_owner(sender):
        # Run anti-spoof checks
        spoof_result = run_anti_spoof_checks(sms)

        direct_owner_opt_in = os.environ.get(
            "JMP_ALLOW_UNAUTHENTICATED_OWNER_DIRECT", ""
        ).lower() in {"1", "true", "yes"}

        if spoof_result.passed and direct_owner_opt_in:
            logger.info(f"Routing verified owner message to main agent: {sender}")
            log_audit_event(
                "routing_decision",
                sender,
                TrustLevel.OWNER_VERIFIED,
                {
                    "action": "main_agent",
                    "spoof_confidence": spoof_result.confidence,
                },
            )
            return RouteDecision(
                action=RouteAction.MAIN_AGENT,
                trust_level=TrustLevel.OWNER_VERIFIED,
                reason="Verified owner, anti-spoof checks passed",
                spoof_result=spoof_result,
                warnings=[i.detail for i in spoof_result.indicators if i.severity == "low"],
            )
        elif spoof_result.passed:
            logger.info(
                "Owner-number message passed heuristics but remains quarantined: %s",
                sender,
            )
            log_audit_event(
                "routing_decision",
                sender,
                TrustLevel.OWNER_VERIFIED,
                {
                    "action": "quarantine",
                    "reason": "direct_owner_disabled",
                    "spoof_confidence": spoof_result.confidence,
                },
            )
            return RouteDecision(
                action=RouteAction.QUARANTINE_AGENT,
                trust_level=TrustLevel.OWNER_VERIFIED,
                reason=(
                    "Owner number recognized, but SMS sender identity is not "
                    "cryptographic proof; direct main-agent routing is disabled"
                ),
                spoof_result=spoof_result,
                warnings=["SMS caller ID can be spoofed; message was quarantined"],
            )
        else:
            # Spoof indicators detected
            logger.warning(f"Spoof indicators detected for owner number: {sender}")
            log_audit_event(
                "spoof_detected",
                sender,
                TrustLevel.OWNER_SUSPICIOUS,
                {
                    "action": "quarantine",
                    "indicators": [i.to_dict() for i in spoof_result.indicators],
                },
            )
            return RouteDecision(
                action=RouteAction.QUARANTINE_AGENT,
                trust_level=TrustLevel.OWNER_SUSPICIOUS,
                reason="Owner number with spoof indicators - quarantining for safety",
                spoof_result=spoof_result,
            )

    # 3. Check if known contact
    if is_known_contact(sender):
        logger.info(f"Routing known contact to quarantine: {sender}")
        log_audit_event(
            "routing_decision",
            sender,
            TrustLevel.KNOWN_CONTACT,
            {
                "action": "quarantine",
            },
        )
        return RouteDecision(
            action=RouteAction.QUARANTINE_AGENT,
            trust_level=TrustLevel.KNOWN_CONTACT,
            reason="Known contact - routing through quarantine",
        )

    # 4. Unknown number
    logger.info(f"Routing unknown number to quarantine: {sender}")
    log_audit_event(
        "routing_decision",
        sender,
        TrustLevel.UNKNOWN,
        {
            "action": "quarantine",
        },
    )
    return RouteDecision(
        action=RouteAction.QUARANTINE_AGENT,
        trust_level=TrustLevel.UNKNOWN,
        reason="Unknown number - routing through quarantine",
    )


def process_incoming_sms(sms: InboundSMS) -> dict:
    """
    Process an incoming SMS and return routing decision with context.

    This is the main entry point for the routing engine.

    Args:
        sms: Incoming SMS message

    Returns:
        Dictionary with routing decision and any additional context
    """
    decision = route_message(sms)

    result = {
        "route": decision.to_dict(),
        "sms": sms.to_dict(),
    }

    # Add owner metadata if applicable
    if decision.trust_level in (TrustLevel.OWNER_VERIFIED, TrustLevel.OWNER_SUSPICIOUS):
        owner_meta = get_owner_metadata(sms.sender)
        if owner_meta:
            result["owner_metadata"] = owner_meta

    # Add contact metadata if applicable
    if decision.trust_level == TrustLevel.KNOWN_CONTACT:
        contacts = get_known_contacts()
        contact_meta = contacts.get(normalize_phone(sms.sender))
        if contact_meta:
            result["contact_metadata"] = contact_meta

    return result


# CLI interface for testing
if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO)

    # Test with sample input
    test_sms = InboundSMS(
        sender=sys.argv[1] if len(sys.argv) > 1 else "+15551234567",
        recipient="+15550001234",  # Your JMP number
        body=sys.argv[2] if len(sys.argv) > 2 else "Test message",
        timestamp=datetime.now(),
        message_id="test-001",
    )

    result = process_incoming_sms(test_sms)
    print(json.dumps(result, indent=2, default=str))
