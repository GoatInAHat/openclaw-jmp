"""
Main Agent Request Handler for JMP Secure SMS Channel

This module handles validated requests from the Quarantine Agent.
It routes requests to appropriate handlers and generates safe responses.

Security Principles:
- NEVER include sensitive data in responses
- ALWAYS log interactions for audit
- Fail secure - when in doubt, escalate
- Assume the Quarantine Agent may be compromised

Author: OpenClaw Contributors
Version: 1.0.0
"""

from __future__ import annotations

import json
import logging
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

try:
    from .paths import CONFIG_DIR, DATA_DIR
except ImportError:  # Direct script execution
    from paths import CONFIG_DIR, DATA_DIR

from api_schema import (
    CannotProcessRequest,
    CheckAvailabilityRequest,
    DeniedResponse,
    EndConversationRequest,
    EndConversationResponse,
    EscalateResponse,
    EscalationType,
    FollowUp,
    FollowUpType,
    GetPublicInfoRequest,
    LeaveMessageRequest,
    # Response types
    MainResponse,
    MiddlemanMessage,
    # Request types
    MiddlemanRequest,
    PublicInfoTopic,
    RelayToOwnerRequest,
    RequestAppointmentRequest,
    RequestCallbackRequest,
    # Other types
    RequestMetadata,
    RequestVerificationRequest,
    SchemaValidationError,
    SuccessResponse,
    TrustLevel,
    Urgency,
    VerificationRequiredResponse,
    VerificationType,
    validate_full_message,
)

# ==============================================================================
# Logging Setup
# ==============================================================================

logger = logging.getLogger("jmp_sms.request_handler")


# ==============================================================================
# Configuration
# ==============================================================================


@dataclass
class HandlerConfig:
    """Configuration for the request handler."""

    # Paths
    audit_log_path: Path = field(default_factory=lambda: DATA_DIR / "audit.jsonl")
    public_info_path: Path = field(default_factory=lambda: CONFIG_DIR / "public_info.json")

    # Security settings
    max_message_length: int = 2000
    allow_unknown_trust_levels: bool = False
    auto_escalate_suspicious: bool = True

    # Rate limiting (per conversation)
    max_requests_per_conversation: int = 50

    # Owner notification settings
    notify_on_escalation: bool = True
    notify_channel: str = "discord"


# ==============================================================================
# Audit Logging
# ==============================================================================


@dataclass
class AuditEntry:
    """An entry in the audit log."""

    timestamp: str
    event_type: str
    request_id: str
    conversation_id: str
    sender_phone: str
    trust_level: str
    request_type: str | None
    response_status: str | None
    details: dict[str, Any]
    security_flags: list[str]


class AuditLogger:
    """Handles audit logging for all request handler operations."""

    def __init__(self, log_path: Path):
        self.log_path = log_path
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, entry: AuditEntry) -> None:
        """Write an audit entry to the log."""
        try:
            with open(self.log_path, "a") as f:
                f.write(
                    json.dumps(
                        {
                            "timestamp": entry.timestamp,
                            "event_type": entry.event_type,
                            "request_id": entry.request_id,
                            "conversation_id": entry.conversation_id,
                            "sender_phone": entry.sender_phone,
                            "trust_level": entry.trust_level,
                            "request_type": entry.request_type,
                            "response_status": entry.response_status,
                            "details": entry.details,
                            "security_flags": entry.security_flags,
                        }
                    )
                    + "\n"
                )
        except Exception as e:
            logger.error(f"Failed to write audit log: {e}")

    def log_request(
        self,
        metadata: RequestMetadata,
        request: MiddlemanRequest,
        response: MainResponse,
    ) -> None:
        """Log a request-response pair."""
        self.log(
            AuditEntry(
                timestamp=datetime.utcnow().isoformat() + "Z",
                event_type="request_handled",
                request_id=metadata.request_id,
                conversation_id=metadata.conversation_id,
                sender_phone=metadata.sender_phone,
                trust_level=metadata.trust_level.value,
                request_type=request.type,
                response_status=response.status,
                details={
                    "request": request.model_dump(mode="json"),
                    "response": response.model_dump(mode="json"),
                },
                security_flags=metadata.security_flags,
            )
        )

    def log_security_event(
        self,
        metadata: RequestMetadata,
        event_type: str,
        details: dict[str, Any],
    ) -> None:
        """Log a security-related event."""
        self.log(
            AuditEntry(
                timestamp=datetime.utcnow().isoformat() + "Z",
                event_type=event_type,
                request_id=metadata.request_id,
                conversation_id=metadata.conversation_id,
                sender_phone=metadata.sender_phone,
                trust_level=metadata.trust_level.value,
                request_type=None,
                response_status=None,
                details=details,
                security_flags=metadata.security_flags,
            )
        )


# ==============================================================================
# Public Information Provider
# ==============================================================================


class PublicInfoProvider:
    """
    Provides public information for external requests.
    Only information explicitly configured as public is available.
    """

    DEFAULT_INFO = {
        PublicInfoTopic.BUSINESS_HOURS: "Available during regular business hours. Best reached via text.",
        PublicInfoTopic.LOCATION: "Location information is not publicly available.",
        PublicInfoTopic.SERVICES: "I'm an AI assistant that can help with scheduling and messages.",
        PublicInfoTopic.CONTACT_METHODS: "You can reach me via text at this number.",
        PublicInfoTopic.FAQ: "For more information, please leave a message and someone will get back to you.",
    }

    def __init__(self, config_path: Path | None = None):
        self.info = self.DEFAULT_INFO.copy()
        if config_path and config_path.exists():
            self._load_config(config_path)

    def _load_config(self, path: Path) -> None:
        """Load public info from configuration file."""
        try:
            with open(path) as f:
                config = json.load(f)
            for topic in PublicInfoTopic:
                if topic.value in config:
                    self.info[topic] = config[topic.value]
        except Exception as e:
            logger.warning(f"Failed to load public info config: {e}")

    def get(self, topic: PublicInfoTopic) -> str:
        """Get public information for a topic."""
        return self.info.get(topic, "Information not available.")


# ==============================================================================
# Request Handlers
# ==============================================================================


class RequestHandlerBase(ABC):
    """Base class for request handlers."""

    def __init__(
        self,
        config: HandlerConfig,
        audit_logger: AuditLogger,
        public_info: PublicInfoProvider,
    ):
        self.config = config
        self.audit = audit_logger
        self.public_info = public_info

    @abstractmethod
    def handle(self, request: MiddlemanRequest, metadata: RequestMetadata) -> MainResponse:
        """Handle a request and return a response."""
        pass

    def _create_success(self, message: str, internal_note: str | None = None) -> SuccessResponse:
        """Create a success response."""
        return SuccessResponse(
            public_message=self._sanitize_message(message),
            internal_note=internal_note,
        )

    def _create_denied(self, reason: str, message: str) -> DeniedResponse:
        """Create a denied response."""
        return DeniedResponse(
            reason=reason,
            public_message=self._sanitize_message(message),
        )

    def _create_escalate(
        self,
        reason: str,
        escalation_type: EscalationType,
        message: str,
    ) -> EscalateResponse:
        """Create an escalate response."""
        return EscalateResponse(
            reason=reason,
            escalation_type=escalation_type,
            public_message=self._sanitize_message(message),
        )

    def _sanitize_message(self, message: str) -> str:
        """Sanitize a message for external delivery."""
        # Truncate if too long
        if len(message) > self.config.max_message_length:
            message = message[: self.config.max_message_length - 3] + "..."
        return message


class GetPublicInfoHandler(RequestHandlerBase):
    """Handler for public information requests."""

    def handle(self, request: GetPublicInfoRequest, metadata: RequestMetadata) -> MainResponse:
        info = self.public_info.get(request.topic)
        return self._create_success(
            info, internal_note=f"Provided public info for topic: {request.topic.value}"
        )


class CheckAvailabilityHandler(RequestHandlerBase):
    """Handler for availability check requests."""

    def handle(self, request: CheckAvailabilityRequest, metadata: RequestMetadata) -> MainResponse:
        # For unknown callers, we don't reveal specific availability
        if metadata.trust_level in (TrustLevel.UNKNOWN, TrustLevel.OWNER_SUSPICIOUS):
            return self._create_escalate(
                reason="Availability checks require owner review for unknown callers",
                escalation_type=EscalationType.OWNER_REVIEW,
                message="I'll check on availability and get back to you. "
                "Someone will reach out to confirm times that work.",
            )

        # For known contacts, provide limited info
        return self._create_success(
            "I've noted your availability request. "
            "Someone will get back to you with available times.",
            internal_note=f"Availability check: {request.date_range_start} to {request.date_range_end}",
        )


class RequestCallbackHandler(RequestHandlerBase):
    """Handler for callback requests."""

    def handle(self, request: RequestCallbackRequest, metadata: RequestMetadata) -> MainResponse:
        urgency_messages = {
            Urgency.LOW: "Your callback request has been noted. Someone will reach out when available.",
            Urgency.NORMAL: "Your callback request has been received. Expect a call back soon.",
            Urgency.HIGH: "Your urgent callback request has been flagged for priority attention.",
        }

        return self._create_escalate(
            reason=f"Callback request: {request.topic} (urgency: {request.urgency.value})",
            escalation_type=EscalationType.CALLBACK_REQUIRED,
            message=urgency_messages.get(request.urgency, urgency_messages[Urgency.NORMAL]),
        )


class RequestAppointmentHandler(RequestHandlerBase):
    """Handler for appointment requests."""

    def handle(self, request: RequestAppointmentRequest, metadata: RequestMetadata) -> MainResponse:
        return self._create_escalate(
            reason=f"Appointment request: {request.purpose} on {request.preferred_date}",
            escalation_type=EscalationType.OWNER_REVIEW,
            message="Your appointment request has been received. "
            "Someone will review your request and confirm the details.",
        )


class LeaveMessageHandler(RequestHandlerBase):
    """Handler for leave message requests."""

    def handle(self, request: LeaveMessageRequest, metadata: RequestMetadata) -> MainResponse:
        callback_note = " They've requested a callback." if request.callback_requested else ""
        sender_info = f" from {request.sender_name}" if request.sender_name else ""

        return self._create_success(
            f"Your message has been received.{' Someone will call you back.' if request.callback_requested else ''}",
            internal_note=f"Message{sender_info}: {request.message[:200]}...{callback_note}",
        )


class RelayToOwnerHandler(RequestHandlerBase):
    """Handler for relay to owner requests."""

    def handle(self, request: RelayToOwnerRequest, metadata: RequestMetadata) -> MainResponse:
        return self._create_escalate(
            reason=f"[{request.category.value}] {request.summary}",
            escalation_type=EscalationType.OWNER_REVIEW,
            message="I've forwarded your request. Someone will review it and get back to you.",
        )


class RequestVerificationHandler(RequestHandlerBase):
    """Handler for verification requests."""

    def handle(
        self, request: RequestVerificationRequest, metadata: RequestMetadata
    ) -> MainResponse:
        verification_id = str(uuid.uuid4())

        return VerificationRequiredResponse(
            verification_type=VerificationType.SMS_CODE,
            public_message="To verify your identity, I'll send you a verification code. "
            "Please reply with the code once you receive it.",
            verification_id=verification_id,
        )


class EndConversationHandler(RequestHandlerBase):
    """Handler for end conversation requests."""

    def handle(self, request: EndConversationRequest, metadata: RequestMetadata) -> MainResponse:
        messages = {
            "resolved": "Glad I could help! Feel free to reach out again anytime.",
            "escalated": "Your request has been forwarded. Someone will be in touch.",
            "user_ended": "Thanks for reaching out. Have a great day!",
            "no_response": "Goodbye! Feel free to text back if you need anything.",
        }

        return EndConversationResponse(
            public_message=messages.get(request.reason.value, messages["resolved"]),
            follow_up=FollowUp(type=FollowUpType.NONE)
            if request.reason.value == "resolved"
            else FollowUp(type=FollowUpType.OWNER_WILL_CONTACT, timeframe="within 24 hours")
            if request.reason.value == "escalated"
            else None,
        )


class CannotProcessHandler(RequestHandlerBase):
    """Handler for cannot process requests."""

    def handle(self, request: CannotProcessRequest, metadata: RequestMetadata) -> MainResponse:
        return self._create_denied(
            reason=request.reason,
            message="I'm sorry, but I wasn't able to process that request. "
            "If you need help, please try rephrasing or leave a message.",
        )


# ==============================================================================
# Main Request Handler
# ==============================================================================


class RequestHandler:
    """
    Main request handler that routes requests to appropriate sub-handlers.

    This is the primary entry point for processing Quarantine Agent requests.
    It enforces security rules and logs all interactions.
    """

    # Security-sensitive patterns that should trigger extra scrutiny
    SUSPICIOUS_PATTERNS = [
        "password",
        "credential",
        "secret",
        "api key",
        "token",
        "ssn",
        "social security",
        "credit card",
        "bank account",
        "private key",
        "seed phrase",
        "wallet",
    ]

    def __init__(self, config: HandlerConfig | None = None):
        self.config = config or HandlerConfig()
        self.audit = AuditLogger(self.config.audit_log_path)
        self.public_info = PublicInfoProvider(self.config.public_info_path)

        # Initialize sub-handlers
        self._handlers: dict[str, RequestHandlerBase] = {
            "get_public_info": GetPublicInfoHandler(self.config, self.audit, self.public_info),
            "check_availability": CheckAvailabilityHandler(
                self.config, self.audit, self.public_info
            ),
            "request_callback": RequestCallbackHandler(self.config, self.audit, self.public_info),
            "request_appointment": RequestAppointmentHandler(
                self.config, self.audit, self.public_info
            ),
            "leave_message": LeaveMessageHandler(self.config, self.audit, self.public_info),
            "relay_to_owner": RelayToOwnerHandler(self.config, self.audit, self.public_info),
            "request_verification": RequestVerificationHandler(
                self.config, self.audit, self.public_info
            ),
            "end_conversation": EndConversationHandler(self.config, self.audit, self.public_info),
            "cannot_process": CannotProcessHandler(self.config, self.audit, self.public_info),
        }

    def handle_message(self, message: MiddlemanMessage) -> MainResponse:
        """
        Handle a complete middleman message.

        Args:
            message: Validated MiddlemanMessage from Quarantine system

        Returns:
            MainResponse to send back
        """
        return self.handle_request(message.request, message.metadata)

    def handle_request(
        self,
        request: MiddlemanRequest,
        metadata: RequestMetadata,
    ) -> MainResponse:
        """
        Handle a validated request.

        Args:
            request: Validated MiddlemanRequest
            metadata: Request metadata

        Returns:
            MainResponse to send back
        """
        # Security check: suspicious patterns
        if self._check_suspicious(request, metadata):
            response = self._handle_suspicious(request, metadata)
            self.audit.log_request(metadata, request, response)
            return response

        # Security check: trust level
        if metadata.trust_level == TrustLevel.BLOCKED:
            response = DeniedResponse(
                reason="blocked",
                public_message="This number has been blocked.",
            )
            self.audit.log_request(metadata, request, response)
            return response

        # Security check: suspicious owner (potential spoof)
        if metadata.trust_level == TrustLevel.OWNER_SUSPICIOUS:
            if self.config.auto_escalate_suspicious:
                response = self._handle_suspicious_owner(request, metadata)
                self.audit.log_request(metadata, request, response)
                return response

        # Route to appropriate handler
        handler = self._handlers.get(request.type)
        if handler is None:
            logger.error(f"No handler for request type: {request.type}")
            response = DeniedResponse(
                reason="internal_error",
                public_message="I'm sorry, something went wrong. Please try again.",
            )
            self.audit.log_request(metadata, request, response)
            return response

        try:
            response = handler.handle(request, metadata)
        except Exception as e:
            logger.exception(f"Handler error for {request.type}: {e}")
            response = DeniedResponse(
                reason="internal_error",
                public_message="I'm sorry, something went wrong. Please try again.",
            )

        self.audit.log_request(metadata, request, response)
        return response

    def handle_raw_json(self, json_data: dict) -> dict:
        """
        Handle a raw JSON request (validates first).

        Args:
            json_data: Raw JSON data containing a MiddlemanMessage

        Returns:
            Response as JSON-serializable dict

        Raises:
            SchemaValidationError: If validation fails
        """
        message = validate_full_message(json_data)
        response = self.handle_message(message)
        return response.model_dump(mode="json")

    def _check_suspicious(self, request: MiddlemanRequest, metadata: RequestMetadata) -> bool:
        """Check if request contains suspicious patterns."""
        # Check all string fields in the request
        request_json = request.model_dump(mode="json")
        request_text = json.dumps(request_json).lower()

        for pattern in self.SUSPICIOUS_PATTERNS:
            if pattern in request_text:
                self.audit.log_security_event(
                    metadata,
                    "suspicious_pattern_detected",
                    {"pattern": pattern, "request_type": request.type},
                )
                return True

        # Check security flags from Quarantine
        high_risk_flags = {"credential_request", "possible_social_engineering", "prompt_injection"}
        if high_risk_flags & set(metadata.security_flags):
            self.audit.log_security_event(
                metadata,
                "high_risk_security_flag",
                {"flags": list(high_risk_flags & set(metadata.security_flags))},
            )
            return True

        return False

    def _handle_suspicious(
        self, request: MiddlemanRequest, metadata: RequestMetadata
    ) -> MainResponse:
        """Handle a suspicious request."""
        return DeniedResponse(
            reason="security_concern",
            public_message="I can't help with that request. "
            "If you need assistance, please try something else.",
        )

    def _handle_suspicious_owner(
        self, request: MiddlemanRequest, metadata: RequestMetadata
    ) -> MainResponse:
        """Handle a request from a suspicious owner number (potential spoof)."""
        return EscalateResponse(
            reason="Owner number with spoof indicators - requires verification",
            escalation_type=EscalationType.OWNER_REVIEW,
            public_message="For security reasons, I need to verify this request. "
            "I'll send a verification code to confirm.",
        )


# ==============================================================================
# Convenience Functions
# ==============================================================================

# Global handler instance
_handler: RequestHandler | None = None


def get_handler(config: HandlerConfig | None = None) -> RequestHandler:
    """Get or create the global request handler."""
    global _handler
    if _handler is None:
        _handler = RequestHandler(config)
    return _handler


def handle_request(request: MiddlemanRequest, metadata: RequestMetadata) -> MainResponse:
    """Handle a request using the global handler."""
    return get_handler().handle_request(request, metadata)


def handle_message(message: MiddlemanMessage) -> MainResponse:
    """Handle a message using the global handler."""
    return get_handler().handle_message(message)


def handle_raw_json(json_data: dict) -> dict:
    """Handle raw JSON using the global handler."""
    return get_handler().handle_raw_json(json_data)


# ==============================================================================
# CLI Entry Point (for testing)
# ==============================================================================

if __name__ == "__main__":
    import sys

    # Example usage
    example_message = {
        "metadata": {
            "request_id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "sender_phone": "+15551234567",
            "trust_level": "unknown",
            "conversation_id": str(uuid.uuid4()),
            "message_count": 1,
            "security_flags": [],
        },
        "request": {
            "type": "leave_message",
            "message": "Hi, please call me back when you can.",
            "sender_name": "John Doe",
            "callback_requested": True,
        },
        "quarantine_response": "I'll make sure your message gets through.",
        "flags": [],
    }

    print("Processing example request...")
    print(f"Input: {json.dumps(example_message, indent=2)}")

    handler = RequestHandler()
    try:
        response = handler.handle_raw_json(example_message)
        print(f"\nResponse: {json.dumps(response, indent=2)}")
    except SchemaValidationError as e:
        print(f"\nValidation error: {e}")
        sys.exit(1)
