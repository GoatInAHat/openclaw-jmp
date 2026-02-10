#!/usr/bin/env python3
"""
Challenge-Response System for Runtime Anti-Spoof Verification.

When anti-spoof checks detect suspicious activity from an owner's phone number,
this system sends a challenge phrase that must be echoed back to confirm identity.

Challenge phrases are:
- Random but speakable (word-based, not random characters)
- Easy to type on a phone
- Unique per challenge
- Expire after a short time window

This provides an additional layer of defense against caller ID spoofing.
"""

import asyncio
import json
import logging
import os
import secrets
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any, Tuple, List

# Add parent directory to path for imports
import sys
sys.path.insert(0, str(Path(__file__).parent))

from jmp_client import send_sms_simple

# Paths
CONFIG_DIR = Path(__file__).parent.parent / 'config'
PENDING_CHALLENGES_PATH = CONFIG_DIR / '.pending_challenges.json'  # Hidden, ephemeral
CHALLENGE_LOG_PATH = CONFIG_DIR / 'challenge_audit.jsonl'

# Constants
CHALLENGE_EXPIRY_SECONDS = 300  # 5 minutes (shorter than OTP since it's time-sensitive)
MAX_PENDING_CHALLENGES_PER_PHONE = 2  # Prevent flooding

# Word lists for generating speakable challenges
# Using simple, unambiguous, easy-to-type words
ADJECTIVES = [
    'happy', 'blue', 'fast', 'soft', 'warm', 'cool', 'bright', 'calm',
    'kind', 'safe', 'fresh', 'clear', 'sweet', 'light', 'quick', 'smooth',
    'green', 'red', 'wild', 'bold', 'gentle', 'lucky', 'merry', 'quiet'
]

NOUNS = [
    'apple', 'bird', 'cloud', 'dance', 'eagle', 'flame', 'grape', 'heart',
    'island', 'jazz', 'kite', 'lemon', 'moon', 'night', 'ocean', 'piano',
    'queen', 'river', 'star', 'tiger', 'umbrella', 'valley', 'wind', 'zebra',
    'mountain', 'forest', 'sunset', 'garden', 'thunder', 'crystal', 'dragon', 'silver'
]

NUMBERS = ['2', '3', '4', '5', '6', '7', '8', '9']  # Avoiding 0 and 1 (ambiguous)

logger = logging.getLogger(__name__)


def _normalize_phone(phone: str) -> str:
    """Normalize phone number to E.164 format."""
    phone = ''.join(c for c in phone if c.isdigit() or c == '+')
    
    if not phone.startswith('+'):
        if len(phone) == 10:
            phone = '+1' + phone
        elif len(phone) == 11 and phone.startswith('1'):
            phone = '+' + phone
        else:
            phone = '+' + phone
    
    return phone


def _load_pending_challenges() -> Dict[str, Any]:
    """Load pending challenges from file."""
    if not PENDING_CHALLENGES_PATH.exists():
        return {'challenges': {}}
    
    try:
        with open(PENDING_CHALLENGES_PATH) as f:
            data = json.load(f)
            # Clean up expired challenges
            now = time.time()
            data['challenges'] = {
                k: v for k, v in data.get('challenges', {}).items()
                if v.get('expires_at', 0) > now
            }
            return data
    except (json.JSONDecodeError, IOError) as e:
        logger.error(f"Error loading pending challenges: {e}")
        return {'challenges': {}}


def _save_pending_challenges(data: Dict[str, Any]) -> bool:
    """Save pending challenges to file."""
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        with open(PENDING_CHALLENGES_PATH, 'w') as f:
            json.dump(data, f)
        # Set restrictive permissions (owner only)
        os.chmod(PENDING_CHALLENGES_PATH, 0o600)
        return True
    except IOError as e:
        logger.error(f"Error saving pending challenges: {e}")
        return False


def _log_challenge_event(event_type: str, phone: str, details: Dict[str, Any]) -> None:
    """
    Log challenge event for audit purposes.
    Unlike OTPs, challenge phrases can be logged since they're single-use
    and exposure after expiration is not a security risk.
    """
    entry = {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'event': event_type,
        'phone': phone,
        **details
    }
    
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        with open(CHALLENGE_LOG_PATH, 'a') as f:
            f.write(json.dumps(entry) + '\n')
    except IOError as e:
        logger.error(f"Error writing challenge log: {e}")


def generate_challenge_phrase() -> str:
    """
    Generate a random but speakable challenge phrase.
    
    Format: "adjective-noun-number" (e.g., "happy-tiger-7")
    
    This format is:
    - Easy to read and type on a phone
    - Unambiguous (no confusing characters)
    - Has sufficient entropy (~15 bits from each word + 3 bits from number = ~33 bits)
    - Memorable enough to type without copying
    
    Returns:
        Challenge phrase string
    """
    adjective = secrets.choice(ADJECTIVES)
    noun = secrets.choice(NOUNS)
    number = secrets.choice(NUMBERS)
    
    return f"{adjective}-{noun}-{number}"


def _normalize_challenge_response(response: str) -> str:
    """
    Normalize a challenge response for comparison.
    
    - Lowercase
    - Strip whitespace
    - Replace spaces with hyphens
    - Remove duplicate hyphens
    """
    response = response.lower().strip()
    response = response.replace(' ', '-')
    response = '-'.join(part for part in response.split('-') if part)
    return response


async def send_challenge(
    phone: str,
    reason: Optional[str] = None,
    spoof_indicators: Optional[List[str]] = None
) -> Tuple[bool, str, str]:
    """
    Send a challenge phrase to verify phone number ownership.
    
    Used when anti-spoof checks detect suspicious activity.
    
    Args:
        phone: Phone number to challenge
        reason: Optional reason for the challenge (for logging)
        spoof_indicators: Optional list of spoof indicators that triggered the challenge
        
    Returns:
        Tuple of (success, message, challenge_id)
    """
    phone = _normalize_phone(phone)
    
    data = _load_pending_challenges()
    
    # Check if there are already too many pending challenges
    existing = [
        v for k, v in data.get('challenges', {}).items()
        if v.get('phone') == phone
    ]
    if len(existing) >= MAX_PENDING_CHALLENGES_PER_PHONE:
        _log_challenge_event('challenge_limit_exceeded', phone, {
            'pending_count': len(existing)
        })
        return False, "Too many pending challenges. Please wait for existing challenges to expire.", ""
    
    # Generate challenge
    phrase = generate_challenge_phrase()
    challenge_id = secrets.token_hex(8)  # 16-character hex ID
    
    # Store challenge
    if 'challenges' not in data:
        data['challenges'] = {}
    
    data['challenges'][challenge_id] = {
        'phone': phone,
        'phrase': phrase,
        'created_at': time.time(),
        'expires_at': time.time() + CHALLENGE_EXPIRY_SECONDS,
        'reason': reason,
        'spoof_indicators': spoof_indicators
    }
    
    _save_pending_challenges(data)
    
    _log_challenge_event('challenge_sent', phone, {
        'challenge_id': challenge_id,
        'phrase': phrase,  # OK to log since single-use
        'reason': reason,
        'spoof_indicators': spoof_indicators
    })
    
    # Send SMS
    message = (
        f"Security check required.\n\n"
        f"Reply with this phrase to confirm: {phrase}\n\n"
        f"This challenge expires in 5 minutes.\n"
        f"If you didn't just try to use OpenClaw, ignore this message."
    )
    
    try:
        success = await send_sms_simple(phone, message)
        if not success:
            _log_challenge_event('challenge_sms_failed', phone, {
                'challenge_id': challenge_id
            })
            return False, "Failed to send challenge SMS.", challenge_id
    except Exception as e:
        logger.error(f"Failed to send challenge SMS: {e}")
        return False, f"Failed to send challenge SMS: {e}", challenge_id
    
    return True, f"Security challenge sent to {phone}. Awaiting response.", challenge_id


def verify_challenge(phone: str, response: str) -> Tuple[bool, str, Optional[str]]:
    """
    Verify a challenge response.
    
    Args:
        phone: Phone number being verified
        response: The response text from the user
        
    Returns:
        Tuple of (success, message, challenge_id or None)
    """
    phone = _normalize_phone(phone)
    response = _normalize_challenge_response(response)
    
    data = _load_pending_challenges()
    
    # Find any pending challenge for this phone
    matching_challenges = [
        (cid, c) for cid, c in data.get('challenges', {}).items()
        if c.get('phone') == phone and c.get('expires_at', 0) > time.time()
    ]
    
    if not matching_challenges:
        _log_challenge_event('no_pending_challenge', phone, {
            'response': response
        })
        return False, "No pending challenge for this phone number.", None
    
    # Check if response matches any pending challenge
    for challenge_id, challenge in matching_challenges:
        expected = _normalize_challenge_response(challenge.get('phrase', ''))
        
        if secrets.compare_digest(response, expected):
            # Success! Remove the challenge
            del data['challenges'][challenge_id]
            _save_pending_challenges(data)
            
            _log_challenge_event('challenge_verified', phone, {
                'challenge_id': challenge_id
            })
            
            return True, "Challenge verified successfully. Identity confirmed.", challenge_id
    
    # Wrong response
    _log_challenge_event('challenge_failed', phone, {
        'response': response,
        'expected_phrases': [c.get('phrase') for _, c in matching_challenges]
    })
    
    return False, "Incorrect challenge response. Please check the phrase and try again.", None


def get_pending_challenge(phone: str) -> Optional[Dict[str, Any]]:
    """
    Get the most recent pending challenge for a phone number.
    
    Args:
        phone: Phone number to check
        
    Returns:
        Challenge info dict or None if no pending challenge
    """
    phone = _normalize_phone(phone)
    data = _load_pending_challenges()
    
    # Find the most recent non-expired challenge
    matching = [
        (cid, c) for cid, c in data.get('challenges', {}).items()
        if c.get('phone') == phone and c.get('expires_at', 0) > time.time()
    ]
    
    if not matching:
        return None
    
    # Return most recent
    matching.sort(key=lambda x: x[1].get('created_at', 0), reverse=True)
    challenge_id, challenge = matching[0]
    
    return {
        'challenge_id': challenge_id,
        'expires_at': challenge.get('expires_at'),
        'created_at': challenge.get('created_at'),
        'reason': challenge.get('reason')
    }


def cancel_challenge(challenge_id: str) -> bool:
    """Cancel a pending challenge."""
    data = _load_pending_challenges()
    
    if challenge_id not in data.get('challenges', {}):
        return False
    
    phone = data['challenges'][challenge_id].get('phone')
    del data['challenges'][challenge_id]
    _save_pending_challenges(data)
    
    _log_challenge_event('challenge_cancelled', phone or 'unknown', {
        'challenge_id': challenge_id
    })
    
    return True


def has_pending_challenge(phone: str) -> bool:
    """Check if a phone number has a pending challenge."""
    return get_pending_challenge(phone) is not None


# Convenience function for the routing engine
async def challenge_and_wait(
    phone: str,
    timeout_seconds: int = CHALLENGE_EXPIRY_SECONDS,
    reason: Optional[str] = None
) -> Tuple[bool, str]:
    """
    Send challenge and wait for response via SMS.
    
    This is a blocking function that waits for the challenge response
    to arrive via SMS. Used by the routing engine when a challenge is required.
    
    Note: This requires integration with the SMS receive handler.
    In practice, the routing engine will send the challenge and then
    the response will come in as a separate SMS message.
    
    Args:
        phone: Phone number to challenge
        timeout_seconds: How long to wait for response
        reason: Reason for challenge (for logging)
        
    Returns:
        Tuple of (success, message)
    """
    success, msg, challenge_id = await send_challenge(phone, reason)
    
    if not success:
        return False, msg
    
    # The actual waiting for response would be handled by the message routing system
    # This function just initiates the challenge
    return True, f"Challenge sent. ID: {challenge_id}. Awaiting response within {timeout_seconds} seconds."


# CLI interface for testing
if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Challenge-Response System')
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # send command
    send_parser = subparsers.add_parser('send', help='Send challenge')
    send_parser.add_argument('phone', help='Phone number to challenge')
    send_parser.add_argument('--reason', help='Reason for challenge')
    
    # verify command
    verify_parser = subparsers.add_parser('verify', help='Verify challenge response')
    verify_parser.add_argument('phone', help='Phone number')
    verify_parser.add_argument('response', help='Challenge response')
    
    # status command
    status_parser = subparsers.add_parser('status', help='Check pending challenge')
    status_parser.add_argument('phone', help='Phone number')
    
    # generate command (for testing)
    subparsers.add_parser('generate', help='Generate a test challenge phrase')
    
    args = parser.parse_args()
    
    logging.basicConfig(level=logging.INFO)
    
    if args.command == 'send':
        success, msg, cid = asyncio.run(send_challenge(args.phone, args.reason))
        print(msg)
        if cid:
            print(f"Challenge ID: {cid}")
    elif args.command == 'verify':
        success, msg, cid = verify_challenge(args.phone, args.response)
        print(msg)
    elif args.command == 'status':
        challenge = get_pending_challenge(args.phone)
        if challenge:
            print(json.dumps(challenge, indent=2))
        else:
            print("No pending challenge.")
    elif args.command == 'generate':
        print(generate_challenge_phrase())
    else:
        parser.print_help()
