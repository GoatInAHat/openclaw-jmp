#!/usr/bin/env python3
"""
Owner Phone Number Verification System.

Handles the secure verification flow for linking phone numbers to trusted owners.
Verification must be initiated from a trusted channel (e.g., Discord) and completed
via SMS OTP confirmation.

Security Requirements:
- OTPs are cryptographically random (secrets module)
- OTPs expire after 10 minutes
- Max 3 verification attempts per hour per number
- All verification attempts are logged (but OTP values are NEVER logged)
"""

import asyncio
import json
import logging
import os
import secrets

# Add parent directory to path for imports
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent))

from jmp_client import send_sms_simple

# Paths
try:
    from .paths import CONFIG_DIR
except ImportError:  # Direct script execution
    from paths import CONFIG_DIR
VERIFIED_OWNERS_PATH = CONFIG_DIR / "verified_owners.json"
PENDING_VERIFICATIONS_PATH = CONFIG_DIR / ".pending_verifications.json"  # Hidden, ephemeral
VERIFICATION_LOG_PATH = CONFIG_DIR / "verification_audit.jsonl"

# Constants
OTP_LENGTH = 6
OTP_EXPIRY_SECONDS = 600  # 10 minutes
MAX_ATTEMPTS_PER_HOUR = 3
RATE_LIMIT_WINDOW_SECONDS = 3600  # 1 hour

logger = logging.getLogger(__name__)


def _normalize_phone(phone: str) -> str:
    """Normalize phone number to E.164 format."""
    phone = "".join(c for c in phone if c.isdigit() or c == "+")

    if not phone.startswith("+"):
        if len(phone) == 10:
            phone = "+1" + phone
        elif len(phone) == 11 and phone.startswith("1"):
            phone = "+" + phone
        else:
            phone = "+" + phone

    return phone


def _load_verified_owners() -> dict[str, Any]:
    """Load verified owners from config file."""
    if not VERIFIED_OWNERS_PATH.exists():
        return {"owners": {}}

    try:
        with open(VERIFIED_OWNERS_PATH) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        logger.error(f"Error loading verified owners: {e}")
        return {"owners": {}}


def _save_verified_owners(data: dict[str, Any]) -> bool:
    """Save verified owners to config file."""
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        with open(VERIFIED_OWNERS_PATH, "w") as f:
            json.dump(data, f, indent=2)
        return True
    except OSError as e:
        logger.error(f"Error saving verified owners: {e}")
        return False


def _load_pending_verifications() -> dict[str, Any]:
    """Load pending verification attempts."""
    if not PENDING_VERIFICATIONS_PATH.exists():
        return {"pending": {}, "attempts": {}}

    try:
        with open(PENDING_VERIFICATIONS_PATH) as f:
            data = json.load(f)
            # Clean up expired entries
            now = time.time()
            data["pending"] = {
                k: v for k, v in data.get("pending", {}).items() if v.get("expires_at", 0) > now
            }
            # Clean up old rate limit entries
            data["attempts"] = {
                k: [t for t in v if t > now - RATE_LIMIT_WINDOW_SECONDS]
                for k, v in data.get("attempts", {}).items()
            }
            data["attempts"] = {k: v for k, v in data["attempts"].items() if v}
            return data
    except (OSError, json.JSONDecodeError) as e:
        logger.error(f"Error loading pending verifications: {e}")
        return {"pending": {}, "attempts": {}}


def _save_pending_verifications(data: dict[str, Any]) -> bool:
    """Save pending verification attempts."""
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        with open(PENDING_VERIFICATIONS_PATH, "w") as f:
            json.dump(data, f)
        # Set restrictive permissions (owner only)
        os.chmod(PENDING_VERIFICATIONS_PATH, 0o600)
        return True
    except OSError as e:
        logger.error(f"Error saving pending verifications: {e}")
        return False


def _log_verification_event(event_type: str, phone: str, details: dict[str, Any]) -> None:
    """
    Log verification event for audit purposes.
    NEVER logs OTP values.
    """
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": event_type,
        "phone": phone,
        **{k: v for k, v in details.items() if k not in ("otp", "code", "otp_hash")},
    }

    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        with open(VERIFICATION_LOG_PATH, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError as e:
        logger.error(f"Error writing verification log: {e}")


def generate_otp() -> str:
    """
    Generate a cryptographically secure 6-digit OTP.

    Uses secrets.randbelow for cryptographic randomness,
    ensuring uniform distribution across all 6-digit codes.

    Returns:
        6-digit string OTP (e.g., "847291")
    """
    # Generate number between 0 and 999999
    otp_int = secrets.randbelow(1000000)
    # Zero-pad to 6 digits
    return f"{otp_int:06d}"


def _check_rate_limit(phone: str) -> tuple[bool, int]:
    """
    Check if phone number is rate limited.

    Returns:
        Tuple of (is_allowed, attempts_remaining)
    """
    data = _load_pending_verifications()
    attempts = data.get("attempts", {}).get(phone, [])

    # Count attempts in the last hour
    now = time.time()
    recent_attempts = [t for t in attempts if t > now - RATE_LIMIT_WINDOW_SECONDS]

    remaining = MAX_ATTEMPTS_PER_HOUR - len(recent_attempts)
    return remaining > 0, max(0, remaining)


def _record_attempt(phone: str) -> None:
    """Record a verification attempt for rate limiting."""
    data = _load_pending_verifications()

    if "attempts" not in data:
        data["attempts"] = {}

    if phone not in data["attempts"]:
        data["attempts"][phone] = []

    data["attempts"][phone].append(time.time())
    _save_pending_verifications(data)


async def initiate_verification(
    phone: str, trusted_channel_id: str, carrier_info: str | None = None
) -> tuple[bool, str]:
    """
    Initiate phone number verification.

    Must be called from a trusted channel (e.g., Discord).
    Generates OTP and sends it via SMS.

    Args:
        phone: Phone number to verify (E.164 format)
        trusted_channel_id: ID of the trusted channel initiating verification
            (e.g., "discord:710610424571363339")
        carrier_info: Optional carrier information for logging

    Returns:
        Tuple of (success, message)
    """
    phone = _normalize_phone(phone)

    # Check rate limit
    is_allowed, remaining = _check_rate_limit(phone)
    if not is_allowed:
        _log_verification_event("rate_limited", phone, {"trusted_channel_id": trusted_channel_id})
        return (
            False,
            f"Rate limit exceeded. Max {MAX_ATTEMPTS_PER_HOUR} verification attempts per hour.",
        )

    # Check if already verified
    owners = _load_verified_owners()
    if phone in owners.get("owners", {}):
        return (
            False,
            f"Phone number {phone} is already verified. Use remove_verified_owner first if you need to re-verify.",
        )

    # Generate OTP
    otp = generate_otp()

    # Store pending verification (with OTP for later verification)
    data = _load_pending_verifications()
    if "pending" not in data:
        data["pending"] = {}

    data["pending"][phone] = {
        "otp": otp,  # Stored only in ephemeral file, never logged
        "trusted_channel_id": trusted_channel_id,
        "carrier_info": carrier_info,
        "created_at": time.time(),
        "expires_at": time.time() + OTP_EXPIRY_SECONDS,
        "attempts": 0,
    }

    _save_pending_verifications(data)
    _record_attempt(phone)

    # Log initiation (without OTP!)
    _log_verification_event(
        "verification_initiated",
        phone,
        {
            "trusted_channel_id": trusted_channel_id,
            "carrier_info": carrier_info,
            "expires_in_seconds": OTP_EXPIRY_SECONDS,
        },
    )

    # Send OTP via SMS
    success = await send_verification_sms(phone, otp)

    if not success:
        _log_verification_event(
            "sms_send_failed", phone, {"trusted_channel_id": trusted_channel_id}
        )
        return False, "Failed to send verification SMS. Please try again."

    _log_verification_event("otp_sent", phone, {"trusted_channel_id": trusted_channel_id})

    return (
        True,
        f"Verification code sent to {phone}. Code expires in 10 minutes. Enter the code in this trusted channel to complete verification.",
    )


async def send_verification_sms(phone: str, otp: str) -> bool:
    """
    Send the verification OTP via SMS.

    Args:
        phone: Recipient phone number
        otp: The OTP code to send

    Returns:
        True if SMS was sent successfully
    """
    message = (
        f"Your OpenClaw verification code is: {otp}\n\n"
        f"Enter this code in Discord to verify ownership of this phone number.\n"
        f"This code expires in 10 minutes.\n\n"
        f"If you didn't request this, ignore this message."
    )

    try:
        return await send_sms_simple(phone, message)
    except Exception as e:
        logger.error(f"Failed to send verification SMS: {e}")
        return False


def verify_otp(phone: str, code: str) -> tuple[bool, str]:
    """
    Verify an OTP code submitted by the user.

    Must be called from the same trusted channel that initiated verification.
    On success, adds the phone number to verified owners.

    Args:
        phone: Phone number being verified
        code: OTP code entered by user

    Returns:
        Tuple of (success, message)
    """
    phone = _normalize_phone(phone)
    code = code.strip()

    data = _load_pending_verifications()
    pending = data.get("pending", {}).get(phone)

    if not pending:
        _log_verification_event("verification_not_found", phone, {})
        return (
            False,
            "No pending verification for this phone number. Please initiate verification first.",
        )

    # Check expiration
    if time.time() > pending.get("expires_at", 0):
        # Clean up expired entry
        del data["pending"][phone]
        _save_pending_verifications(data)
        _log_verification_event(
            "verification_expired", phone, {"trusted_channel_id": pending.get("trusted_channel_id")}
        )
        return False, "Verification code has expired. Please request a new code."

    # Increment attempt counter
    pending["attempts"] = pending.get("attempts", 0) + 1
    data["pending"][phone] = pending
    _save_pending_verifications(data)

    # Check if too many wrong attempts on this specific verification
    if pending["attempts"] > 3:
        del data["pending"][phone]
        _save_pending_verifications(data)
        _log_verification_event(
            "too_many_attempts",
            phone,
            {
                "trusted_channel_id": pending.get("trusted_channel_id"),
                "attempts": pending["attempts"],
            },
        )
        return False, "Too many incorrect attempts. Please request a new verification code."

    # Verify the code (constant-time comparison)
    if not secrets.compare_digest(code, pending.get("otp", "")):
        _log_verification_event(
            "invalid_otp",
            phone,
            {
                "trusted_channel_id": pending.get("trusted_channel_id"),
                "attempts": pending["attempts"],
            },
        )
        remaining = 3 - pending["attempts"]
        return False, f"Invalid verification code. {remaining} attempts remaining."

    # Success! Add to verified owners
    metadata = {
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "verified_via": pending.get("trusted_channel_id"),
        "carrier_at_verification": pending.get("carrier_info"),
        "last_verified": datetime.now(timezone.utc).isoformat(),
    }

    success = add_verified_owner(phone, metadata)

    if not success:
        return False, "Failed to save verified owner. Please try again."

    # Clean up pending verification
    del data["pending"][phone]
    _save_pending_verifications(data)

    _log_verification_event(
        "verification_success",
        phone,
        {
            "trusted_channel_id": pending.get("trusted_channel_id"),
            "carrier_info": pending.get("carrier_info"),
        },
    )

    return True, f"✓ Phone number {phone} has been verified and linked to your account."


def add_verified_owner(phone: str, metadata: dict[str, Any]) -> bool:
    """
    Add a phone number to verified owners.

    Args:
        phone: Phone number in E.164 format
        metadata: Owner metadata dict containing:
            - verified_at: ISO timestamp
            - verified_via: Trusted channel ID
            - carrier_at_verification: Optional carrier info
            - last_verified: ISO timestamp

    Returns:
        True if saved successfully
    """
    phone = _normalize_phone(phone)

    data = _load_verified_owners()

    if "owners" not in data:
        data["owners"] = {}

    data["owners"][phone] = metadata

    success = _save_verified_owners(data)

    if success:
        _log_verification_event("owner_added", phone, metadata)

    return success


def remove_verified_owner(phone: str) -> tuple[bool, str]:
    """
    Remove a phone number from verified owners.

    Args:
        phone: Phone number to remove

    Returns:
        Tuple of (success, message)
    """
    phone = _normalize_phone(phone)

    data = _load_verified_owners()

    if phone not in data.get("owners", {}):
        return False, f"Phone number {phone} is not in verified owners."

    del data["owners"][phone]

    success = _save_verified_owners(data)

    if success:
        _log_verification_event("owner_removed", phone, {})
        return True, f"Phone number {phone} has been removed from verified owners."
    else:
        return False, "Failed to save changes."


def is_verified_owner(phone: str) -> bool:
    """Check if a phone number is a verified owner."""
    phone = _normalize_phone(phone)
    data = _load_verified_owners()
    return phone in data.get("owners", {})


def get_verified_owner(phone: str) -> dict[str, Any] | None:
    """Get verified owner info if exists."""
    phone = _normalize_phone(phone)
    data = _load_verified_owners()
    return data.get("owners", {}).get(phone)


def list_verified_owners() -> dict[str, dict[str, Any]]:
    """List all verified owners."""
    data = _load_verified_owners()
    return data.get("owners", {})


def update_last_verified(phone: str) -> bool:
    """Update the last_verified timestamp for an owner."""
    phone = _normalize_phone(phone)
    data = _load_verified_owners()

    if phone not in data.get("owners", {}):
        return False

    data["owners"][phone]["last_verified"] = datetime.now(timezone.utc).isoformat()
    return _save_verified_owners(data)


# CLI interface for testing
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Owner Verification System")
    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # initiate command
    init_parser = subparsers.add_parser("initiate", help="Initiate verification")
    init_parser.add_argument("phone", help="Phone number to verify")
    init_parser.add_argument("--channel", default="cli:test", help="Trusted channel ID")

    # verify command
    verify_parser = subparsers.add_parser("verify", help="Verify OTP")
    verify_parser.add_argument("phone", help="Phone number")
    verify_parser.add_argument("code", help="OTP code")

    # list command
    subparsers.add_parser("list", help="List verified owners")

    # remove command
    remove_parser = subparsers.add_parser("remove", help="Remove verified owner")
    remove_parser.add_argument("phone", help="Phone number to remove")

    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)

    if args.command == "initiate":
        success, msg = asyncio.run(initiate_verification(args.phone, args.channel))
        print(msg)
    elif args.command == "verify":
        success, msg = verify_otp(args.phone, args.code)
        print(msg)
    elif args.command == "list":
        owners = list_verified_owners()
        if owners:
            print(json.dumps(owners, indent=2))
        else:
            print("No verified owners.")
    elif args.command == "remove":
        success, msg = remove_verified_owner(args.phone)
        print(msg)
    else:
        parser.print_help()
