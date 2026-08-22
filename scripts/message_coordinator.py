#!/usr/bin/env python3
"""
Message Coordinator - Main orchestration layer for JMP SMS security.

This is the central coordinator that:
1. Receives InboundSMS from XMPP listener
2. Calls routing engine to determine trust level
3. Routes to Main Agent (owner) or Quarantine Agent (others)
4. Sends replies back via XMPP
5. Logs everything for audit
"""

import asyncio
import logging
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from anti_spoof import run_anti_spoof_checks
from api_schema import TrustLevel as APITrustLevel

# Local imports (will be created by other subagents)
from audit_logger import AuditEventType, AuditLogger, get_audit_logger
from main_agent_interface import (
    MainAgentInterface,
    MainResponse,
    MainResponseStatus,
    get_response_template,
)
from quarantine_handler import QuarantineResult as QuarantineResponse
from quarantine_handler import process_quarantine_sms
from rate_limiter import RateLimiter, RateLimitResult, get_rate_limiter
from routing_engine import (
    InboundSMS,
    TrustLevel,
)
from routing_engine import (
    is_blocked as _is_blocked,
)
from routing_engine import (
    is_verified_owner as _is_verified_owner,
)
from routing_engine import (
    route_message as _route_message,
)


class RoutingEngine:
    """Adapter from the functional routing module to the coordinator API."""

    def route_message(self, sms):
        result = _route_message(sms)
        return type(
            "Route",
            (),
            {
                "action": result.action.value if hasattr(result.action, "value") else result.action,
                "trust": result.trust_level.value
                if hasattr(result.trust_level, "value")
                else result.trust_level,
                "reason": result.reason,
                "spoof_indicators": result.spoof_result.indicators if result.spoof_result else [],
                "warnings": result.warnings,
            },
        )()

    def is_verified_owner(self, phone):
        return _is_verified_owner(phone)

    def is_blocked(self, phone):
        return _is_blocked(phone)


class AntiSpoofChecker:
    def check(self, sms):
        return run_anti_spoof_checks(sms)


class QuarantineHandler:
    """Async adapter around the provider-backed quarantine processor."""

    async def process(self, sms, trust_level, conversation_id):
        api_trust = APITrustLevel(
            trust_level.value if hasattr(trust_level, "value") else trust_level
        )
        return await asyncio.to_thread(
            process_quarantine_sms,
            sms,
            api_trust,
            conversation_id,
        )


logger = logging.getLogger(__name__)


@dataclass
class ConversationState:
    """Track state of an ongoing conversation."""

    conversation_id: str
    sender: str
    trust_level: str
    started_at: str
    message_count: int = 0
    last_message_at: str | None = None
    pending_verification: str | None = None
    security_flags: list[str] = field(default_factory=list)


class MessageCoordinator:
    """
    Central coordinator for all SMS message processing.

    Orchestrates the flow:
    SMS → Routing → Trust Decision → Agent → Response → SMS
    """

    # Conversation timeout in seconds (30 minutes)
    CONVERSATION_TIMEOUT = 1800

    def __init__(
        self,
        routing_engine: RoutingEngine | None = None,
        anti_spoof_checker: AntiSpoofChecker | None = None,
        quarantine_handler: QuarantineHandler | None = None,
        rate_limiter: RateLimiter | None = None,
        audit_logger: AuditLogger | None = None,
        main_interface: MainAgentInterface | None = None,
        send_sms_callback: Callable | None = None,
        notify_owner_callback: Callable | None = None,
    ):
        """
        Initialize the coordinator.

        Args:
            routing_engine: Determines trust level and routing
            anti_spoof_checker: Checks for spoofing attempts
            quarantine_handler: Handles quarantine agent interactions
            rate_limiter: Enforces rate limits
            audit_logger: Logs all events
            main_interface: Interface to main agent
            send_sms_callback: Async function to send SMS
            notify_owner_callback: Async function to notify owner
        """
        self.routing_engine = routing_engine or RoutingEngine()
        self.anti_spoof = anti_spoof_checker or AntiSpoofChecker()
        self.quarantine = quarantine_handler or QuarantineHandler()
        self.rate_limiter = rate_limiter or get_rate_limiter()
        self.audit = audit_logger or get_audit_logger()
        self.main_interface = main_interface or MainAgentInterface()

        self._send_sms = send_sms_callback
        self._notify_owner = notify_owner_callback

        # Active conversations by phone number
        self._conversations: dict[str, ConversationState] = {}

        # Pending spoof challenges
        self._pending_challenges: dict[str, dict] = {}

        # Lock for thread safety
        self._lock = asyncio.Lock()

    async def process_message(self, sms: InboundSMS) -> str | None:
        """
        Process an incoming SMS message.

        This is the main entry point for all incoming messages.

        Args:
            sms: The incoming SMS message

        Returns:
            Response text to send back, or None if no response needed
        """

        try:
            # Log receipt
            self.audit.log_sms_received(
                sender=sms.sender,
                body=sms.body,
                details={"message_id": sms.message_id, "carrier_info": sms.carrier_info},
            )

            # Step 1: Check rate limits
            rate_result = await self._check_rate_limits(sms)
            if not rate_result.allowed:
                return await self._handle_rate_limited(sms, rate_result)

            # Step 2: Check for pending spoof challenge response
            challenge_response = await self._check_challenge_response(sms)
            if challenge_response is not None:
                return challenge_response

            # Step 3: Get or create conversation
            conversation = await self._get_or_create_conversation(sms)
            conversation.message_count += 1
            conversation.last_message_at = datetime.utcnow().isoformat() + "Z"

            # Step 4: Route the message
            route = self.routing_engine.route_message(sms)

            self.audit.log_routing_decision(
                sender=sms.sender,
                trust_level=route.trust if hasattr(route, "trust") else "unknown",
                action=route.action,
                spoof_indicators=getattr(route, "spoof_indicators", None),
            )

            # Step 5: Handle based on route
            if route.action == "drop":
                # Blocked or filtered - no response
                self.audit.log(
                    AuditEventType.BLOCKED,
                    sender=sms.sender,
                    details={"reason": getattr(route, "reason", "blocked")},
                )
                return None

            elif route.action == "main_agent":
                # Owner verified - direct to main agent
                return await self._handle_owner_message(sms, conversation, route)

            elif route.action in {"quarantine", "quarantine_agent"}:
                # External/suspicious - route through quarantine
                return await self._handle_quarantine_message(sms, conversation, route)

            elif route.action == "challenge":
                # Suspected spoof - send challenge
                return await self._send_spoof_challenge(sms, route)

            else:
                logger.warning(f"Unknown route action: {route.action}")
                return get_response_template("cannot_process")

        except Exception as e:
            logger.exception(f"Error processing message from {sms.sender}")
            self.audit.log_error(
                error_type="processing_error", error_message=str(e), sender=sms.sender
            )
            return get_response_template("cannot_process")

        finally:
            # Record rate limit usage
            is_unknown = not self.routing_engine.is_verified_owner(sms.sender)
            self.rate_limiter.record_message(sms.sender, is_unknown)

    async def _check_rate_limits(self, sms: InboundSMS) -> RateLimitResult:
        """Check all applicable rate limits."""
        is_unknown = not self.routing_engine.is_verified_owner(sms.sender)
        result = self.rate_limiter.check_message(sms.sender, is_unknown)

        if not result.allowed:
            self.audit.log_rate_limit(
                sender=sms.sender,
                limit_type=result.limit_type.value if result.limit_type else "unknown",
                current_count=result.current_count,
                limit=result.limit,
            )

        return result

    async def _handle_rate_limited(self, sms: InboundSMS, rate_result: RateLimitResult) -> str:
        """Handle a rate-limited message."""
        # Only respond once per rate limit window to avoid making it worse
        response = get_response_template("rate_limited")

        # Don't spam the rate-limited sender
        if rate_result.current_count <= rate_result.limit + 1:
            await self._send_response(sms.sender, response)

        return response

    async def _check_challenge_response(self, sms: InboundSMS) -> str | None:
        """Check if this message is a response to a spoof challenge."""
        async with self._lock:
            if sms.sender not in self._pending_challenges:
                return None

            challenge = self._pending_challenges[sms.sender]

            # Check if challenge expired
            challenge_time = datetime.fromisoformat(challenge["timestamp"].rstrip("Z"))
            if (datetime.utcnow() - challenge_time).total_seconds() > 600:  # 10 min
                del self._pending_challenges[sms.sender]
                return None

            # Check response
            expected_code = challenge["code"]
            if sms.body.strip() == expected_code:
                # Challenge passed
                del self._pending_challenges[sms.sender]

                self.audit.log(
                    AuditEventType.SPOOF_CHALLENGE_RESPONSE,
                    sender=sms.sender,
                    details={"result": "passed"},
                )

                # Update conversation trust
                if sms.sender in self._conversations:
                    self._conversations[sms.sender].trust_level = TrustLevel.OWNER_VERIFIED

                return "Identity verified! How can I help you?"

            else:
                # Wrong code
                self.audit.log(
                    AuditEventType.SPOOF_CHALLENGE_RESPONSE,
                    sender=sms.sender,
                    details={"result": "failed", "provided": sms.body.strip()[:20]},
                )

                return "That code doesn't match. Please try again or use a different verification method."

    async def _get_or_create_conversation(self, sms: InboundSMS) -> ConversationState:
        """Get existing conversation or create a new one."""
        async with self._lock:
            if sms.sender in self._conversations:
                conv = self._conversations[sms.sender]

                # Check for timeout
                if conv.last_message_at:
                    last_time = datetime.fromisoformat(conv.last_message_at.rstrip("Z"))
                    if (datetime.utcnow() - last_time).total_seconds() > self.CONVERSATION_TIMEOUT:
                        # Start new conversation
                        del self._conversations[sms.sender]
                    else:
                        return conv

            # Create new conversation
            conv = ConversationState(
                conversation_id=str(uuid.uuid4()),
                sender=sms.sender,
                trust_level=TrustLevel.UNKNOWN,
                started_at=datetime.utcnow().isoformat() + "Z",
            )
            self._conversations[sms.sender] = conv
            return conv

    async def _handle_owner_message(
        self, sms: InboundSMS, conversation: ConversationState, route: Any
    ) -> str:
        """Handle a message from a verified owner."""
        conversation.trust_level = TrustLevel.OWNER_VERIFIED

        # Create owner message
        warnings = []
        if hasattr(route, "warnings") and route.warnings:
            warnings = route.warnings

        owner_msg = self.main_interface.create_owner_message(
            sender=sms.sender,
            body=sms.body,
            conversation_id=conversation.conversation_id,
            warnings=warnings,
        )

        self.audit.log_main_request(
            sender=sms.sender,
            request_type="owner_direct",
            conversation_id=conversation.conversation_id,
        )

        # Send to main agent
        response = await self.main_interface.send_owner_message(owner_msg)

        if response:
            self.audit.log_main_response(
                sender=sms.sender, status="success", conversation_id=conversation.conversation_id
            )
            await self._send_response(sms.sender, response, conversation.conversation_id)
            return response
        else:
            error_response = "Sorry, I couldn't process that right now. Please try again."
            await self._send_response(sms.sender, error_response, conversation.conversation_id)
            return error_response

    async def _handle_quarantine_message(
        self, sms: InboundSMS, conversation: ConversationState, route: Any
    ) -> str:
        """Handle a message routed to quarantine agent."""
        trust_level = route.trust if hasattr(route, "trust") else TrustLevel.UNKNOWN
        conversation.trust_level = trust_level

        # Add any spoof indicators to flags
        if hasattr(route, "spoof_indicators") and route.spoof_indicators:
            for indicator in route.spoof_indicators:
                flag = f"{indicator.get('type', 'unknown')}:{indicator.get('severity', 'low')}"
                if flag not in conversation.security_flags:
                    conversation.security_flags.append(flag)

        # Check quarantine rate limit
        quarantine_result = self.rate_limiter.check_quarantine_request(sms.sender)
        if not quarantine_result.allowed:
            return get_response_template("rate_limited")

        self.rate_limiter.record_quarantine_request(sms.sender)

        # Process through quarantine agent
        quarantine_response = await self.quarantine.process(
            sms, trust_level, conversation.conversation_id
        )

        self.audit.log_quarantine_interaction(
            sender=sms.sender,
            request_type=quarantine_response.request.get("type", "unknown")
            if quarantine_response.request
            else "none",
            response=quarantine_response.response,
            flags=quarantine_response.flags,
        )

        # Add any new flags
        for flag in quarantine_response.flags:
            if flag not in conversation.security_flags:
                conversation.security_flags.append(flag)

        # Check for security flags that need owner notification
        if self._should_notify_owner(quarantine_response.flags):
            await self._notify_security_alert(sms, quarantine_response)

        # If quarantine generated a request for main agent, send it
        if quarantine_response.request:
            main_response = await self._forward_to_main_agent(
                sms, conversation, quarantine_response.request, quarantine_response.flags
            )

            # Use main agent's response if available, else quarantine's
            if main_response and main_response.public_message:
                final_response = main_response.public_message
            else:
                final_response = quarantine_response.response
        else:
            final_response = quarantine_response.response

        await self._send_response(sms.sender, final_response, conversation.conversation_id)
        return final_response

    async def _forward_to_main_agent(
        self, sms: InboundSMS, conversation: ConversationState, request: dict, flags: list[str]
    ) -> MainResponse | None:
        """Forward a quarantine request to the main agent."""
        middleman_request = self.main_interface.create_middleman_request(
            request_type=request.get("type", "unknown"),
            sender_phone=sms.sender,
            trust_level=conversation.trust_level,
            conversation_id=conversation.conversation_id,
            message_count=conversation.message_count,
            security_flags=flags,
            **{k: v for k, v in request.items() if k != "type"},
        )

        self.audit.log_main_request(
            sender=sms.sender,
            request_type=request.get("type", "unknown"),
            conversation_id=conversation.conversation_id,
            trust_level=conversation.trust_level,
        )

        response = await self.main_interface.send_middleman_request(middleman_request)

        if response:
            self.audit.log_main_response(
                sender=sms.sender,
                status=response.status.value,
                conversation_id=conversation.conversation_id,
            )

            # Handle escalations
            if response.status == MainResponseStatus.ESCALATE:
                await self._handle_escalation(sms, conversation, response)

        return response

    async def _send_spoof_challenge(self, sms: InboundSMS, route: Any) -> str:
        """Send a spoof challenge to verify identity."""
        # Check challenge rate limit
        challenge_result = self.rate_limiter.check_spoof_challenge(sms.sender)
        if not challenge_result.allowed:
            # Too many challenges - just route to quarantine
            self.audit.log_security_alert(
                alert_type="challenge_limit_exceeded",
                sender=sms.sender,
                description="Too many spoof challenges, routing to quarantine",
            )
            # Create a mock route for quarantine
            mock_route = type(
                "Route",
                (),
                {
                    "action": "quarantine_agent",
                    "trust": TrustLevel.OWNER_SUSPICIOUS,
                    "spoof_indicators": getattr(route, "spoof_indicators", []),
                    "warnings": [],
                },
            )()
            conv = await self._get_or_create_conversation(sms)
            return await self._handle_quarantine_message(sms, conv, mock_route)

        # Generate challenge code
        import random

        code = "".join(str(random.randint(0, 9)) for _ in range(6))

        # Store challenge
        async with self._lock:
            self._pending_challenges[sms.sender] = {
                "code": code,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "original_message": sms.body[:100],
                "indicators": getattr(route, "spoof_indicators", []),
            }

        self.rate_limiter.record_spoof_challenge(sms.sender)

        self.audit.log(
            AuditEventType.SPOOF_CHALLENGE_SENT,
            sender=sms.sender,
            spoof_indicators=getattr(route, "spoof_indicators", []),
        )

        challenge_message = f"Security verification required. Reply with this code: {code}"
        await self._send_response(sms.sender, challenge_message)

        return challenge_message

    def _should_notify_owner(self, flags: list[str]) -> bool:
        """Determine if security flags warrant owner notification."""
        serious_flags = [
            "possible_social_engineering",
            "credential_request",
            "sensitive_data_request",
            "impersonation_attempt",
            "high_severity_spoof",
        ]
        return any(flag in flags for flag in serious_flags)

    async def _notify_security_alert(
        self, sms: InboundSMS, quarantine_response: QuarantineResponse
    ) -> None:
        """Notify owner of a security concern."""
        alert_message = f"""🚨 Security Alert - SMS

From: {sms.sender}
Flags: {", ".join(quarantine_response.flags)}
Message preview: {sms.body[:50]}...

Quarantine handled with: "{quarantine_response.response[:50]}..."
"""

        self.audit.log_security_alert(
            alert_type="quarantine_security_flag",
            sender=sms.sender,
            description=f"Flags: {quarantine_response.flags}",
            severity="medium",
        )

        if self._notify_owner:
            try:
                await self._notify_owner(alert_message, urgent=True)
            except Exception as e:
                logger.error(f"Failed to notify owner: {e}")

    async def _handle_escalation(
        self, sms: InboundSMS, conversation: ConversationState, response: MainResponse
    ) -> None:
        """Handle an escalation from main agent."""
        self.audit.log_escalation(
            sender=sms.sender,
            reason=response.reason or "unknown",
            escalation_type=response.escalation_type.value
            if response.escalation_type
            else "owner_review",
            conversation_id=conversation.conversation_id,
        )

        notification = self.main_interface.format_escalation_notification(
            {
                "type": response.escalation_type.value
                if response.escalation_type
                else "owner_review",
                "sender": sms.sender,
                "reason": response.reason,
                "request_summary": conversation.security_flags,
            }
        )

        if self._notify_owner:
            try:
                await self._notify_owner(notification, urgent=True)
            except Exception as e:
                logger.error(f"Failed to send escalation notification: {e}")

    async def _send_response(
        self, recipient: str, message: str, conversation_id: str | None = None
    ) -> bool:
        """Send an SMS response."""
        if not self._send_sms:
            logger.error("No send_sms callback configured")
            return False

        try:
            await self._send_sms(recipient, message)

            self.audit.log_sms_sent(
                recipient=recipient, body=message, conversation_id=conversation_id
            )

            return True
        except Exception as e:
            logger.error(f"Failed to send SMS to {recipient}: {e}")
            self.audit.log_error(error_type="send_failed", error_message=str(e), sender=recipient)
            return False

    def get_conversation(self, phone: str) -> ConversationState | None:
        """Get the current conversation state for a phone number."""
        return self._conversations.get(phone)

    def get_stats(self) -> dict:
        """Get coordinator statistics."""
        return {
            "active_conversations": len(self._conversations),
            "pending_challenges": len(self._pending_challenges),
            "rate_limiter": self.rate_limiter.get_stats(),
        }

    async def cleanup(self) -> None:
        """Clean up expired conversations and challenges."""
        now = datetime.utcnow()

        async with self._lock:
            # Clean up expired conversations
            expired_convs = []
            for phone, conv in self._conversations.items():
                if conv.last_message_at:
                    last = datetime.fromisoformat(conv.last_message_at.rstrip("Z"))
                    if (now - last).total_seconds() > self.CONVERSATION_TIMEOUT:
                        expired_convs.append(phone)

            for phone in expired_convs:
                del self._conversations[phone]

            # Clean up expired challenges
            expired_challenges = []
            for phone, challenge in self._pending_challenges.items():
                challenge_time = datetime.fromisoformat(challenge["timestamp"].rstrip("Z"))
                if (now - challenge_time).total_seconds() > 600:
                    expired_challenges.append(phone)

            for phone in expired_challenges:
                del self._pending_challenges[phone]

        if expired_convs or expired_challenges:
            logger.info(
                f"Cleaned up {len(expired_convs)} conversations, {len(expired_challenges)} challenges"
            )


# Convenience function to create coordinator with JMP client integration
def create_coordinator_with_jmp(
    jmp_client, notify_callback: Callable | None = None
) -> MessageCoordinator:
    """
    Create a MessageCoordinator with JMP client integration.

    Args:
        jmp_client: JMPClient instance
        notify_callback: Optional callback for owner notifications

    Returns:
        Configured MessageCoordinator
    """

    async def send_sms(recipient: str, message: str):
        jmp_client.send_sms(recipient, message)

    return MessageCoordinator(send_sms_callback=send_sms, notify_owner_callback=notify_callback)
