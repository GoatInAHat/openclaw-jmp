#!/usr/bin/env python3
"""
JMP.chat XMPP Client for SMS messaging.

This is the core client library for interacting with JMP.chat via XMPP.
SMS messages are sent/received through the Cheogram gateway.
"""

import asyncio
import json
import logging
import os
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

import slixmpp

try:
    from .paths import CREDENTIALS_PATH, MESSAGE_LOG_PATH
except ImportError:  # Direct script execution
    from paths import CREDENTIALS_PATH, MESSAGE_LOG_PATH

logger = logging.getLogger(__name__)


def load_credentials(path: Path = CREDENTIALS_PATH) -> dict:
    """Load JMP credentials from JSON or environment variables.

    ``JMP_JABBER_ID`` and ``JMP_PASSWORD`` are the required environment
    variables when the JSON file does not exist. File permissions are checked
    on POSIX systems because this file contains an XMPP password.
    """
    path = Path(path).expanduser()
    if path.exists():
        if os.name == "posix" and path.stat().st_mode & 0o077:
            raise PermissionError(
                f"Credential file {path} is accessible by group/others; run chmod 600 {path}"
            )
        with path.open(encoding="utf-8") as handle:
            credentials = json.load(handle)
    else:
        credentials = {
            "jabber_id": os.environ.get("JMP_JABBER_ID"),
            "password": os.environ.get("JMP_PASSWORD"),
            "phone_number": os.environ.get("JMP_PHONE_NUMBER"),
            "xmpp_server": os.environ.get("JMP_XMPP_SERVER"),
            "sms_gateway": os.environ.get("JMP_SMS_GATEWAY", "cheogram.com"),
        }

    missing = [key for key in ("jabber_id", "password") if not credentials.get(key)]
    if missing:
        raise ValueError(
            f"Missing JMP credential fields: {', '.join(missing)}. "
            f"Create {path} or set JMP_JABBER_ID and JMP_PASSWORD."
        )
    return credentials


def phone_to_jid(phone: str, gateway: str = "cheogram.com") -> str:
    """
    Convert a phone number to a Cheogram JID.

    Args:
        phone: Phone number (e.g., "+15551234567" or "5551234567")
        gateway: SMS gateway domain

    Returns:
        JID string (e.g., "+15551234567@cheogram.com")
    """
    # Clean the phone number
    phone = "".join(c for c in phone if c.isdigit() or c == "+")

    # Ensure US format with + prefix
    if not phone.startswith("+"):
        if len(phone) == 10:
            phone = "+1" + phone
        elif len(phone) == 11 and phone.startswith("1"):
            phone = "+" + phone
        else:
            phone = "+" + phone

    return f"{phone}@{gateway}"


def jid_to_phone(jid: str) -> str:
    """Extract phone number from Cheogram JID."""
    local_part = str(jid).split("@")[0]
    return local_part


class JMPClient(slixmpp.ClientXMPP):
    """
    XMPP client for JMP.chat SMS messaging.

    Connects to the user's XMPP server and routes SMS through Cheogram gateway.
    """

    def __init__(
        self,
        jid: str,
        password: str,
        sms_gateway: str = "cheogram.com",
        message_callback: Callable | None = None,
        log_messages: bool = True,
    ):
        """
        Initialize the JMP client.

        Args:
            jid: Jabber ID (e.g., "user@server.com")
            password: XMPP password
            sms_gateway: SMS gateway domain (default: cheogram.com)
            message_callback: Optional callback for received messages
            log_messages: Whether to log messages to file
        """
        super().__init__(jid, password)

        self.sms_gateway = sms_gateway
        self.message_callback = message_callback
        self.log_messages = log_messages
        self.connected_event = asyncio.Event()
        self.auth_failed = False

        # Register event handlers
        self.add_event_handler("session_start", self._on_session_start)
        self.add_event_handler("message", self._on_message)
        self.add_event_handler("failed_auth", self._on_failed_auth)
        self.add_event_handler("disconnected", self._on_disconnected)

        # Register plugins
        self.register_plugin("xep_0030")  # Service Discovery
        self.register_plugin("xep_0199")  # XMPP Ping

    async def _on_session_start(self, event):
        """Handle session start."""
        logger.info(f"Connected as {self.boundjid.full}")
        self.send_presence()
        await self.get_roster()
        self.connected_event.set()

    def _on_message(self, msg):
        """Handle incoming messages."""
        if msg["type"] not in ("chat", "normal"):
            return

        sender = str(msg["from"]).split("/")[0]
        body = msg["body"]

        # Only process messages from the SMS gateway
        if not sender.endswith(f"@{self.sms_gateway}"):
            return

        phone = jid_to_phone(sender)
        timestamp = datetime.utcnow().isoformat()

        logger.info(f"SMS from {phone}: {body[:50]}...")

        # Log message
        if self.log_messages:
            self._log_message(
                {"direction": "incoming", "phone": phone, "body": body, "timestamp": timestamp}
            )

        # Call user callback
        if self.message_callback:
            try:
                self.message_callback(phone, body, timestamp)
            except Exception as e:
                logger.error(f"Message callback error: {e}")

    def _on_failed_auth(self, event):
        """Handle authentication failure."""
        # Note: slixmpp may report failed_auth for channel binding issues
        # but then succeed with a fallback mechanism
        logger.warning("Authentication attempt failed (may retry with fallback)")

    def _on_disconnected(self, event):
        """Handle disconnection."""
        logger.info("Disconnected from XMPP server")
        self.connected_event.clear()

    def _log_message(self, message_data: dict):
        """Log a message to the history file."""
        try:
            MESSAGE_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
            with open(MESSAGE_LOG_PATH, "a") as f:
                f.write(json.dumps(message_data) + "\n")
        except Exception as e:
            logger.error(f"Failed to log message: {e}")

    def send_sms(self, phone: str, body: str) -> bool:
        """
        Send an SMS message.

        Args:
            phone: Recipient phone number
            body: Message text

        Returns:
            True if message was sent (not guaranteed delivery)
        """
        jid = phone_to_jid(phone, self.sms_gateway)

        logger.info(f"Sending SMS to {phone}: {body[:50]}...")

        self.send_message(mto=jid, mbody=body, mtype="chat")

        # Log outgoing message
        if self.log_messages:
            self._log_message(
                {
                    "direction": "outgoing",
                    "phone": phone,
                    "body": body,
                    "timestamp": datetime.utcnow().isoformat(),
                }
            )

        return True

    async def wait_connected(self, timeout: float = 15.0) -> bool:
        """
        Wait for connection to be established.

        Args:
            timeout: Maximum seconds to wait

        Returns:
            True if connected, False if timed out or auth failed
        """
        try:
            await asyncio.wait_for(self.connected_event.wait(), timeout=timeout)
            return True
        except asyncio.TimeoutError:
            logger.error("Connection timeout")
            return False


async def send_sms_simple(
    phone: str, message: str, credentials_path: Path = CREDENTIALS_PATH
) -> bool:
    """
    Simple one-shot SMS send function.

    Args:
        phone: Recipient phone number
        message: Message text
        credentials_path: Path to credentials JSON

    Returns:
        True if message was sent
    """
    creds = load_credentials(credentials_path)

    client = JMPClient(
        creds["jabber_id"], creds["password"], creds.get("sms_gateway", "cheogram.com")
    )

    client.connect()

    if not await client.wait_connected():
        return False

    client.send_sms(phone, message)

    # Brief wait for message to be sent
    await asyncio.sleep(2)

    client.disconnect()
    return True


def get_message_history(
    phone: str | None = None, limit: int = 50, log_path: Path = MESSAGE_LOG_PATH
) -> list[dict]:
    """
    Retrieve message history.

    Args:
        phone: Filter by phone number (optional)
        limit: Maximum messages to return
        log_path: Path to message log file

    Returns:
        List of message dictionaries
    """
    if not log_path.exists():
        return []

    messages = []
    with open(log_path) as f:
        for line in f:
            try:
                msg = json.loads(line.strip())
                if phone is None or msg.get("phone") == phone:
                    messages.append(msg)
            except json.JSONDecodeError:
                continue

    # Return most recent
    return messages[-limit:]
