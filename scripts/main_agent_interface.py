#!/usr/bin/env python3
"""
Interface for communicating with the Main Agent.

Handles formatting of messages, requests, and responses between
the SMS security layer and the main OpenClaw agent.
"""

import json
import logging
import uuid
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class MainResponseStatus(str, Enum):
    """Status of main agent responses."""

    SUCCESS = "success"
    DENIED = "denied"
    ESCALATE = "escalate"
    VERIFICATION_REQUIRED = "verification_required"
    END_CONVERSATION = "end_conversation"


class EscalationType(str, Enum):
    """Types of escalation."""

    OWNER_REVIEW = "owner_review"
    CALLBACK_REQUIRED = "callback_required"
    IN_PERSON_REQUIRED = "in_person_required"


@dataclass
class OwnerMessage:
    """
    Message from a verified owner to be sent to main agent.

    This represents a fully trusted message that should be processed
    with the main agent's full capabilities.
    """

    sender: str  # E.164 phone number
    body: str
    timestamp: str
    message_id: str
    conversation_id: str

    # Trust verification
    verified: bool = True
    anti_spoof_passed: bool = True
    warnings: list[str] = field(default_factory=list)

    # Context
    channel: str = "sms"
    reply_to: str | None = None

    def to_agent_format(self) -> str:
        """Format for main agent consumption."""
        header = f"📱 SMS from Owner ({self.sender})"
        if self.warnings:
            header += f" ⚠️ Warnings: {', '.join(self.warnings)}"

        return f"""{header}
---
{self.body}
---
Conversation ID: {self.conversation_id}
Message ID: {self.message_id}
Time: {self.timestamp}"""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class MiddlemanRequest:
    """
    Typed request from Quarantine Agent to Main Agent.

    This is the ONLY way external parties can communicate with
    the main agent - through a strictly typed API.
    """

    request_id: str
    request_type: str
    timestamp: str
    sender_phone: str
    trust_level: str
    conversation_id: str
    message_count: int
    security_flags: list[str] = field(default_factory=list)

    # Type-specific fields
    topic: str | None = None
    date_range: dict[str, str] | None = None
    preferred_date: str | None = None
    preferred_time: str | None = None
    purpose: str | None = None
    duration: int | None = None
    urgency: str | None = None
    message: str | None = None
    sender_name: str | None = None
    callback_requested: bool | None = None
    summary: str | None = None
    category: str | None = None
    suggested_action: str | None = None
    reason: str | None = None
    original_intent: str | None = None

    def to_dict(self) -> dict:
        """Convert to dict, excluding None values."""
        d = asdict(self)
        return {k: v for k, v in d.items() if v is not None}

    def to_agent_format(self) -> str:
        """Format for main agent consumption."""
        # Build header with security info
        trust_emoji = {
            "owner_suspicious": "⚠️",
            "known_contact": "📇",
            "unknown": "❓",
            "blocked": "🚫",
        }.get(self.trust_level, "❓")

        header = f"{trust_emoji} Quarantine Request from {self.sender_phone}"

        if self.security_flags:
            header += f"\n🚨 Security Flags: {', '.join(self.security_flags)}"

        # Build request body
        body_parts = [
            f"Request Type: {self.request_type}",
            f"Trust Level: {self.trust_level}",
            f"Messages in conversation: {self.message_count}",
        ]

        # Add type-specific fields
        if self.topic:
            body_parts.append(f"Topic: {self.topic}")
        if self.purpose:
            body_parts.append(f"Purpose: {self.purpose}")
        if self.preferred_date:
            body_parts.append(f"Preferred Date: {self.preferred_date}")
        if self.preferred_time:
            body_parts.append(f"Preferred Time: {self.preferred_time}")
        if self.duration:
            body_parts.append(f"Duration: {self.duration} minutes")
        if self.urgency:
            body_parts.append(f"Urgency: {self.urgency}")
        if self.message:
            body_parts.append(f"Message: {self.message}")
        if self.sender_name:
            body_parts.append(f"Sender Name: {self.sender_name}")
        if self.summary:
            body_parts.append(f"Summary: {self.summary}")
        if self.category:
            body_parts.append(f"Category: {self.category}")
        if self.suggested_action:
            body_parts.append(f"Suggested Action: {self.suggested_action}")
        if self.callback_requested:
            body_parts.append("Callback Requested: Yes")
        if self.reason:
            body_parts.append(f"Reason: {self.reason}")
        if self.original_intent:
            body_parts.append(f"Original Intent: {self.original_intent}")

        return f"""{header}
---
{chr(10).join(body_parts)}
---
Request ID: {self.request_id}
Conversation ID: {self.conversation_id}
Time: {self.timestamp}"""


@dataclass
class MainResponse:
    """Response from main agent to be sent back via SMS."""

    status: MainResponseStatus
    public_message: str

    # Optional fields
    internal_note: str | None = None
    reason: str | None = None
    escalation_type: EscalationType | None = None
    verification_type: str | None = None
    verification_id: str | None = None
    follow_up: dict[str, str] | None = None

    def to_dict(self) -> dict:
        d = {"status": self.status.value, "public_message": self.public_message}
        if self.internal_note:
            d["internal_note"] = self.internal_note
        if self.reason:
            d["reason"] = self.reason
        if self.escalation_type:
            d["escalation_type"] = self.escalation_type.value
        if self.verification_type:
            d["verification_type"] = self.verification_type
        if self.verification_id:
            d["verification_id"] = self.verification_id
        if self.follow_up:
            d["follow_up"] = self.follow_up
        return d

    @classmethod
    def success(cls, message: str, internal_note: str | None = None) -> "MainResponse":
        return cls(
            status=MainResponseStatus.SUCCESS, public_message=message, internal_note=internal_note
        )

    @classmethod
    def denied(cls, message: str, reason: str) -> "MainResponse":
        return cls(status=MainResponseStatus.DENIED, public_message=message, reason=reason)

    @classmethod
    def escalate(cls, message: str, reason: str, escalation_type: EscalationType) -> "MainResponse":
        return cls(
            status=MainResponseStatus.ESCALATE,
            public_message=message,
            reason=reason,
            escalation_type=escalation_type,
        )

    @classmethod
    def verification_required(
        cls, message: str, verification_type: str, verification_id: str
    ) -> "MainResponse":
        return cls(
            status=MainResponseStatus.VERIFICATION_REQUIRED,
            public_message=message,
            verification_type=verification_type,
            verification_id=verification_id,
        )

    @classmethod
    def end_conversation(
        cls, message: str, follow_up: dict[str, str] | None = None
    ) -> "MainResponse":
        return cls(
            status=MainResponseStatus.END_CONVERSATION, public_message=message, follow_up=follow_up
        )


class MainAgentInterface:
    """
    Interface for communicating with the main OpenClaw agent.

    This class handles:
    - Formatting owner messages for direct processing
    - Formatting quarantine requests for typed API
    - Parsing main agent responses
    - Managing escalation flows
    """

    def __init__(
        self, send_to_main: Callable | None = None, escalation_callback: Callable | None = None
    ):
        """
        Initialize the interface.

        Args:
            send_to_main: Async function to send messages to main agent
            escalation_callback: Callback for escalations (notifications)
        """
        self._send_to_main = send_to_main
        self._escalation_callback = escalation_callback

        # Track pending requests
        self._pending_requests: dict[str, MiddlemanRequest] = {}

    def create_owner_message(
        self,
        sender: str,
        body: str,
        conversation_id: str | None = None,
        warnings: list[str] | None = None,
    ) -> OwnerMessage:
        """Create an owner message for main agent processing."""
        return OwnerMessage(
            sender=sender,
            body=body,
            timestamp=datetime.utcnow().isoformat() + "Z",
            message_id=str(uuid.uuid4()),
            conversation_id=conversation_id or str(uuid.uuid4()),
            warnings=warnings or [],
        )

    def create_middleman_request(
        self,
        request_type: str,
        sender_phone: str,
        trust_level: str,
        conversation_id: str,
        message_count: int = 1,
        security_flags: list[str] | None = None,
        **kwargs,
    ) -> MiddlemanRequest:
        """Create a typed middleman request for main agent."""
        return MiddlemanRequest(
            request_id=str(uuid.uuid4()),
            request_type=request_type,
            timestamp=datetime.utcnow().isoformat() + "Z",
            sender_phone=sender_phone,
            trust_level=trust_level,
            conversation_id=conversation_id,
            message_count=message_count,
            security_flags=security_flags or [],
            **kwargs,
        )

    async def send_owner_message(self, message: OwnerMessage) -> str | None:
        """
        Send an owner message to the main agent.

        Returns:
            The main agent's response text, or None on failure
        """
        if not self._send_to_main:
            logger.error("No send_to_main callback configured")
            return None

        formatted = message.to_agent_format()

        try:
            response = await self._send_to_main(
                formatted,
                channel="sms",
                sender=message.sender,
                conversation_id=message.conversation_id,
            )
            return response
        except Exception as e:
            logger.error(f"Failed to send owner message: {e}")
            return None

    async def send_middleman_request(self, request: MiddlemanRequest) -> MainResponse | None:
        """
        Send a middleman request to the main agent.

        Returns:
            Parsed MainResponse, or None on failure
        """
        if not self._send_to_main:
            logger.error("No send_to_main callback configured")
            return None

        # Track pending request
        self._pending_requests[request.request_id] = request

        formatted = request.to_agent_format()

        try:
            response_text = await self._send_to_main(
                formatted,
                channel="sms_quarantine",
                sender=request.sender_phone,
                conversation_id=request.conversation_id,
                request_type=request.request_type,
            )

            # Parse response
            response = self.parse_main_response(response_text, request)

            # Handle escalations
            if response and response.status == MainResponseStatus.ESCALATE:
                await self._handle_escalation(request, response)

            return response

        except Exception as e:
            logger.error(f"Failed to send middleman request: {e}")
            return None
        finally:
            # Clean up pending request
            self._pending_requests.pop(request.request_id, None)

    def parse_main_response(
        self, response_text: str, request: MiddlemanRequest | None = None
    ) -> MainResponse:
        """
        Parse main agent's response into typed MainResponse.

        The main agent should respond with a public message that's
        safe to send to the external party. This function extracts
        the relevant parts.
        """
        if not response_text:
            return MainResponse.denied(
                "I'm sorry, I couldn't process your request right now.", "no_response"
            )

        # Check for JSON response format
        if response_text.strip().startswith("{"):
            try:
                data = json.loads(response_text)
                return self._parse_json_response(data)
            except json.JSONDecodeError:
                pass

        # Look for structured markers in text response
        lines = response_text.strip().split("\n")

        # Check for status markers
        status = MainResponseStatus.SUCCESS
        public_message = response_text
        internal_note = None

        for line in lines:
            lower = line.lower()
            if lower.startswith("[status:"):
                status_str = line.split(":")[1].strip().rstrip("]").lower()
                if status_str in [s.value for s in MainResponseStatus]:
                    status = MainResponseStatus(status_str)
            elif lower.startswith("[internal:"):
                internal_note = line.split(":", 1)[1].strip().rstrip("]")
            elif lower.startswith("[escalate:"):
                status = MainResponseStatus.ESCALATE

        # Extract public message (remove any internal markers)
        public_lines = []
        for line in lines:
            if not line.lower().startswith("["):
                public_lines.append(line)

        if public_lines:
            public_message = "\n".join(public_lines).strip()

        return MainResponse(
            status=status, public_message=public_message, internal_note=internal_note
        )

    def _parse_json_response(self, data: dict) -> MainResponse:
        """Parse JSON-formatted main response."""
        status_str = data.get("status", "success")

        try:
            status = MainResponseStatus(status_str)
        except ValueError:
            status = MainResponseStatus.SUCCESS

        return MainResponse(
            status=status,
            public_message=data.get("public_message", data.get("message", "")),
            internal_note=data.get("internal_note"),
            reason=data.get("reason"),
            escalation_type=EscalationType(data["escalation_type"])
            if data.get("escalation_type")
            else None,
            verification_type=data.get("verification_type"),
            verification_id=data.get("verification_id"),
            follow_up=data.get("follow_up"),
        )

    async def _handle_escalation(self, request: MiddlemanRequest, response: MainResponse) -> None:
        """Handle an escalation to the owner."""
        if not self._escalation_callback:
            logger.warning("No escalation callback configured")
            return

        escalation_data = {
            "type": response.escalation_type.value if response.escalation_type else "owner_review",
            "reason": response.reason or "Review required",
            "sender": request.sender_phone,
            "request_type": request.request_type,
            "conversation_id": request.conversation_id,
            "request_summary": request.summary or request.purpose or request.message,
            "security_flags": request.security_flags,
        }

        try:
            await self._escalation_callback(escalation_data)
        except Exception as e:
            logger.error(f"Escalation callback failed: {e}")

    def format_escalation_notification(self, escalation_data: dict) -> str:
        """Format an escalation for owner notification."""
        esc_type = escalation_data.get("type", "review")
        sender = escalation_data.get("sender", "Unknown")
        reason = escalation_data.get("reason", "Review required")
        request_type = escalation_data.get("request_type", "unknown")
        summary = escalation_data.get("request_summary", "")
        flags = escalation_data.get("security_flags", [])

        notification = f"""📱 SMS Escalation ({esc_type})
From: {sender}
Request: {request_type}
Reason: {reason}"""

        if summary:
            notification += f"\nSummary: {summary}"

        if flags:
            notification += f"\n🚨 Security Flags: {', '.join(flags)}"

        notification += "\n\n[Approve] [Decline] [Respond]"

        return notification

    async def notify_owner(
        self, notification: str, channel: str = "discord", urgent: bool = False
    ) -> bool:
        """
        Send a notification to the owner via a trusted channel.

        This is used for security alerts, escalations, and important updates.
        """
        if self._escalation_callback:
            try:
                await self._escalation_callback(
                    {"notification": notification, "channel": channel, "urgent": urgent}
                )
                return True
            except Exception as e:
                logger.error(f"Failed to notify owner: {e}")
                return False
        return False


# Default response templates for common situations
RESPONSE_TEMPLATES = {
    "rate_limited": "I'm receiving too many messages right now. Please try again in a few minutes.",
    "blocked": "This number is not able to send messages to this service.",
    "spoof_challenge": "For security, please reply with the code that was just sent to verify your identity.",
    "verification_sent": "I've sent a verification code. Please reply with that code to continue.",
    "cannot_process": "I'm sorry, I wasn't able to process that request. Could you try rephrasing?",
    "escalated": "I've forwarded your request. Someone will get back to you soon.",
    "no_sensitive_info": "I'm not able to provide that information via SMS.",
    "callback_scheduled": "Got it! We'll call you back at the time you specified.",
    "message_received": "Thank you! Your message has been received.",
}


def get_response_template(key: str, **kwargs) -> str:
    """Get a response template, optionally with formatting."""
    template = RESPONSE_TEMPLATES.get(key, RESPONSE_TEMPLATES["cannot_process"])
    return template.format(**kwargs) if kwargs else template
