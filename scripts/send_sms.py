#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["slixmpp>=1.8,<2"]
# ///
"""
CLI tool to send SMS via JMP.chat.

Usage:
    python send_sms.py <phone_number> <message>
    python send_sms.py +15551234567 "Hello from OpenClaw!"
"""

import argparse
import asyncio
import logging
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from jmp_client import CREDENTIALS_PATH, send_sms_simple


def main():
    parser = argparse.ArgumentParser(description="Send SMS via JMP.chat")
    parser.add_argument("phone", help="Recipient phone number (e.g., +15551234567)")
    parser.add_argument("message", help="Message text to send")
    parser.add_argument(
        "--credentials",
        "-c",
        type=Path,
        default=CREDENTIALS_PATH,
        help="Path to credentials JSON file",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")

    args = parser.parse_args()

    # Setup logging
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s - %(levelname)s - %(message)s")

    # Send the message
    print(f"Sending SMS to {args.phone}...")

    success = asyncio.run(send_sms_simple(args.phone, args.message, args.credentials))

    if success:
        print("✓ Message sent successfully!")
        return 0
    else:
        print("✗ Failed to send message")
        return 1


if __name__ == "__main__":
    sys.exit(main())
