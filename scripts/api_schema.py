"""
Typed API Schema for JMP Secure SMS Channel

This module defines the SECURITY BOUNDARY between Quarantine Agent and Main Agent.
All requests from Quarantine MUST conform to these schemas - this is enforced, not optional.

Security Principles:
- Exhaustive enumeration: Only explicitly defined request types are allowed
- Strict validation: Unknown fields are rejected, required fields are enforced
- Type safety: All fields have explicit types that are validated
- Paranoid defaults: Anything ambiguous fails closed

Author: OpenClaw Contributors
Version: 1.0.0
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime
from enum import Enum
from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    ValidationError,
    field_validator,
    model_validator,
)


def _to_camel(value: str) -> str:
    """Accept camelCase JSON from model prompts while keeping Python snake_case."""
    head, *tail = value.split("_")
    return head + "".join(part.capitalize() for part in tail)


# ==============================================================================
# Custom Exceptions
# ==============================================================================


class SchemaValidationError(Exception):
    """Raised when request/response fails schema validation."""

    def __init__(self, message: str, errors: list[dict] | None = None):
        super().__init__(message)
        self.message = message
        self.errors = errors or []

    def __str__(self) -> str:
        if self.errors:
            error_details = "; ".join(
                f"{e.get('loc', 'unknown')}: {e.get('msg', 'validation error')}"
                for e in self.errors
            )
            return f"{self.message}: {error_details}"
        return self.message


class UnknownRequestTypeError(SchemaValidationError):
    """Raised when an unknown request type is encountered."""

    def __init__(self, request_type: str):
        super().__init__(
            f"Unknown request type '{request_type}' - this is not allowed",
            errors=[{"loc": ("type",), "msg": f"'{request_type}' is not a valid request type"}],
        )
        self.request_type = request_type


class SecurityViolationError(SchemaValidationError):
    """Raised when a request appears to violate security constraints."""

    def __init__(self, message: str, violation_type: str):
        super().__init__(f"Security violation ({violation_type}): {message}")
        self.violation_type = violation_type


# ==============================================================================
# Enums and Constants
# ==============================================================================


class TrustLevel(str, Enum):
    """Trust levels for incoming messages."""

    OWNER_VERIFIED = "owner_verified"
    OWNER_SUSPICIOUS = "owner_suspicious"
    KNOWN_CONTACT = "known_contact"
    UNKNOWN = "unknown"
    BLOCKED = "blocked"


class Urgency(str, Enum):
    """Urgency levels for callback requests."""

    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"


class PublicInfoTopic(str, Enum):
    """Allowed topics for public information requests."""

    BUSINESS_HOURS = "business_hours"
    LOCATION = "location"
    SERVICES = "services"
    CONTACT_METHODS = "contact_methods"
    FAQ = "faq"


class MessageCategory(str, Enum):
    """Categories for relay messages."""

    QUESTION = "question"
    REQUEST = "request"
    COMPLAINT = "complaint"
    OTHER = "other"


class VerificationPurpose(str, Enum):
    """Purposes for verification requests."""

    BECOME_KNOWN_CONTACT = "become_known_contact"
    VERIFY_IDENTITY = "verify_identity"


class EndConversationReason(str, Enum):
    """Reasons for ending a conversation."""

    RESOLVED = "resolved"
    ESCALATED = "escalated"
    USER_ENDED = "user_ended"
    NO_RESPONSE = "no_response"


class ResponseStatus(str, Enum):
    """Status codes for main agent responses."""

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


class VerificationType(str, Enum):
    """Types of verification."""

    SMS_CODE = "sms_code"
    CALLBACK = "callback"
    EMAIL = "email"


class FollowUpType(str, Enum):
    """Types of follow-up."""

    OWNER_WILL_CONTACT = "owner_will_contact"
    NONE = "none"


# ==============================================================================
# Phone Number Validation
# ==============================================================================

# E.164 format: + followed by 1-15 digits
E164_PATTERN = re.compile(r"^\+[1-9]\d{1,14}$")


def validate_e164(phone: str) -> str:
    """Validate and normalize E.164 phone number."""
    if not E164_PATTERN.match(phone):
        raise ValueError(f"Invalid E.164 phone number: {phone}")
    return phone


# ==============================================================================
# Request Metadata
# ==============================================================================


class RequestMetadata(BaseModel):
    """
    Metadata attached to every request from Quarantine Agent.
    This provides context for Main Agent's decision making.
    """

    model_config = ConfigDict(
        extra="forbid",  # Reject unknown fields
        frozen=True,  # Immutable
        alias_generator=_to_camel,
        populate_by_name=True,
    )

    request_id: str = Field(description="UUID for tracking this specific request")
    timestamp: str = Field(description="ISO 8601 timestamp when request was created")
    sender_phone: str = Field(description="E.164 formatted phone number of sender")
    trust_level: TrustLevel = Field(description="Trust level assigned by routing engine")
    conversation_id: str = Field(description="Groups messages in same conversation")
    message_count: int = Field(ge=1, description="Number of messages in this conversation so far")
    security_flags: list[str] = Field(
        default_factory=list, description="Security flags from Quarantine Agent"
    )

    @field_validator("request_id")
    @classmethod
    def validate_request_id(cls, v: str) -> str:
        """Ensure request_id is a valid UUID."""
        try:
            uuid.UUID(v)
        except ValueError as exc:
            raise ValueError("request_id must be a valid UUID") from exc
        return v

    @field_validator("timestamp")
    @classmethod
    def validate_timestamp(cls, v: str) -> str:
        """Ensure timestamp is valid ISO 8601."""
        try:
            datetime.fromisoformat(v.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("timestamp must be valid ISO 8601 format") from exc
        return v

    @field_validator("sender_phone")
    @classmethod
    def validate_phone(cls, v: str) -> str:
        """Ensure phone is valid E.164."""
        return validate_e164(v)

    @field_validator("conversation_id")
    @classmethod
    def validate_conversation_id(cls, v: str) -> str:
        """Ensure conversation_id is a valid UUID."""
        try:
            uuid.UUID(v)
        except ValueError as exc:
            raise ValueError("conversation_id must be a valid UUID") from exc
        return v


# ==============================================================================
# Request Types (Quarantine → Main)
# ==============================================================================


class GetPublicInfoRequest(BaseModel):
    """Request for public information only."""

    model_config = ConfigDict(
        extra="forbid", frozen=True, alias_generator=_to_camel, populate_by_name=True
    )

    type: Literal["get_public_info"] = "get_public_info"
    topic: PublicInfoTopic = Field(description="The specific topic to get information about")


class CheckAvailabilityRequest(BaseModel):
    """Request to check availability for scheduling."""

    model_config = ConfigDict(
        extra="forbid", frozen=True, alias_generator=_to_camel, populate_by_name=True
    )

    type: Literal["check_availability"] = "check_availability"
    date_range_start: str = Field(description="ISO 8601 date for start of range")
    date_range_end: str = Field(description="ISO 8601 date for end of range")
    purpose: str | None = Field(
        default=None, max_length=500, description="Purpose for checking availability"
    )

    @field_validator("date_range_start", "date_range_end")
    @classmethod
    def validate_date(cls, v: str) -> str:
        """Validate ISO date format."""
        try:
            datetime.fromisoformat(v.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("Must be valid ISO 8601 date") from exc
        return v

    @model_validator(mode="after")
    def validate_date_range(self) -> CheckAvailabilityRequest:
        """Ensure start is before end."""
        start = datetime.fromisoformat(self.date_range_start.replace("Z", "+00:00"))
        end = datetime.fromisoformat(self.date_range_end.replace("Z", "+00:00"))
        if start > end:
            raise ValueError("date_range_start must be before date_range_end")
        return self


class RequestCallbackRequest(BaseModel):
    """Request for the owner to call back."""

    model_config = ConfigDict(
        extra="forbid", frozen=True, alias_generator=_to_camel, populate_by_name=True
    )

    type: Literal["request_callback"] = "request_callback"
    topic: str = Field(min_length=1, max_length=500, description="Topic for the callback")
    urgency: Urgency = Field(default=Urgency.NORMAL, description="Urgency level")
    preferred_time: str | None = Field(
        default=None, max_length=100, description="Preferred time for callback (free text)"
    )


class RequestAppointmentRequest(BaseModel):
    """Request to schedule an appointment."""

    model_config = ConfigDict(
        extra="forbid", frozen=True, alias_generator=_to_camel, populate_by_name=True
    )

    type: Literal["request_appointment"] = "request_appointment"
    purpose: str = Field(min_length=1, max_length=500, description="Purpose of the appointment")
    preferred_date: str = Field(description="Preferred date (ISO 8601 or description)")
    preferred_time: str | None = Field(default=None, max_length=100, description="Preferred time")
    duration: int | None = Field(
        default=None,
        ge=5,
        le=480,  # Max 8 hours
        description="Duration in minutes",
    )


class LeaveMessageRequest(BaseModel):
    """Leave a message for the owner."""

    model_config = ConfigDict(
        extra="forbid", frozen=True, alias_generator=_to_camel, populate_by_name=True
    )

    type: Literal["leave_message"] = "leave_message"
    message: str = Field(min_length=1, max_length=2000, description="The message to leave")
    sender_name: str | None = Field(default=None, max_length=100, description="Name of the sender")
    callback_requested: StrictBool = Field(description="Whether sender wants a callback")


class RelayToOwnerRequest(BaseModel):
    """Relay a complex request to the owner for handling."""

    model_config = ConfigDict(
        extra="forbid", frozen=True, alias_generator=_to_camel, populate_by_name=True
    )

    type: Literal["relay_to_owner"] = "relay_to_owner"
    summary: str = Field(
        min_length=1, max_length=1000, description="Quarantine's summary of the request"
    )
    category: MessageCategory = Field(description="Category of the request")
    suggested_action: str | None = Field(
        default=None, max_length=500, description="Suggested action for owner"
    )


class RequestVerificationRequest(BaseModel):
    """Request to become a verified contact."""

    model_config = ConfigDict(
        extra="forbid", frozen=True, alias_generator=_to_camel, populate_by_name=True
    )

    type: Literal["request_verification"] = "request_verification"
    purpose: VerificationPurpose = Field(description="Purpose of verification")


class EndConversationRequest(BaseModel):
    """Signal that conversation is ending."""

    model_config = ConfigDict(
        extra="forbid", frozen=True, alias_generator=_to_camel, populate_by_name=True
    )

    type: Literal["end_conversation"] = "end_conversation"
    reason: EndConversationReason = Field(description="Reason for ending")


class CannotProcessRequest(BaseModel):
    """Indicate that the request cannot be processed."""

    model_config = ConfigDict(
        extra="forbid", frozen=True, alias_generator=_to_camel, populate_by_name=True
    )

    type: Literal["cannot_process"] = "cannot_process"
    reason: str = Field(
        min_length=1, max_length=500, description="Why the request cannot be processed"
    )
    original_intent: str | None = Field(
        default=None, max_length=500, description="What the user was trying to do"
    )


# Union of all valid request types
MiddlemanRequest = Annotated[
    GetPublicInfoRequest
    | CheckAvailabilityRequest
    | RequestCallbackRequest
    | RequestAppointmentRequest
    | LeaveMessageRequest
    | RelayToOwnerRequest
    | RequestVerificationRequest
    | EndConversationRequest
    | CannotProcessRequest,
    Field(discriminator="type"),
]

# List of all valid request type names (for validation)
VALID_REQUEST_TYPES = frozenset(
    {
        "get_public_info",
        "check_availability",
        "request_callback",
        "request_appointment",
        "leave_message",
        "relay_to_owner",
        "request_verification",
        "end_conversation",
        "cannot_process",
    }
)


# ==============================================================================
# Response Types (Main → Quarantine)
# ==============================================================================


class FollowUp(BaseModel):
    """Follow-up information for end_conversation."""

    model_config = ConfigDict(
        extra="forbid", frozen=True, alias_generator=_to_camel, populate_by_name=True
    )

    type: FollowUpType
    timeframe: str | None = Field(default=None, max_length=100)


class SuccessResponse(BaseModel):
    """Successful response."""

    model_config = ConfigDict(
        extra="forbid", frozen=True, alias_generator=_to_camel, populate_by_name=True
    )

    status: Literal["success"] = "success"
    public_message: str = Field(
        min_length=1, max_length=2000, description="Safe message to send to external party"
    )
    internal_note: str | None = Field(
        default=None, max_length=1000, description="For logging only - NOT sent to external"
    )


class DeniedResponse(BaseModel):
    """Request denied response."""

    model_config = ConfigDict(
        extra="forbid", frozen=True, alias_generator=_to_camel, populate_by_name=True
    )

    status: Literal["denied"] = "denied"
    reason: str = Field(min_length=1, max_length=500, description="Safe explanation")
    public_message: str = Field(
        min_length=1, max_length=2000, description="What to tell external party"
    )


class EscalateResponse(BaseModel):
    """Escalation required response."""

    model_config = ConfigDict(
        extra="forbid", frozen=True, alias_generator=_to_camel, populate_by_name=True
    )

    status: Literal["escalate"] = "escalate"
    reason: str = Field(min_length=1, max_length=500)
    escalation_type: EscalationType
    public_message: str = Field(
        min_length=1, max_length=2000, description="What to tell external party while waiting"
    )


class VerificationRequiredResponse(BaseModel):
    """Verification required response."""

    model_config = ConfigDict(
        extra="forbid", frozen=True, alias_generator=_to_camel, populate_by_name=True
    )

    status: Literal["verification_required"] = "verification_required"
    verification_type: VerificationType
    public_message: str = Field(min_length=1, max_length=2000)
    verification_id: str = Field(description="ID to track verification flow")

    @field_validator("verification_id")
    @classmethod
    def validate_verification_id(cls, v: str) -> str:
        """Ensure verification_id is a valid UUID."""
        try:
            uuid.UUID(v)
        except ValueError as exc:
            raise ValueError("verification_id must be a valid UUID") from exc
        return v


class EndConversationResponse(BaseModel):
    """End conversation response."""

    model_config = ConfigDict(
        extra="forbid", frozen=True, alias_generator=_to_camel, populate_by_name=True
    )

    status: Literal["end_conversation"] = "end_conversation"
    public_message: str = Field(min_length=1, max_length=2000)
    follow_up: FollowUp | None = None


# Union of all valid response types
MainResponse = Annotated[
    SuccessResponse
    | DeniedResponse
    | EscalateResponse
    | VerificationRequiredResponse
    | EndConversationResponse,
    Field(discriminator="status"),
]

# List of all valid response status names (for validation)
VALID_RESPONSE_STATUSES = frozenset(
    {
        "success",
        "denied",
        "escalate",
        "verification_required",
        "end_conversation",
    }
)


# ==============================================================================
# Full Message Wrapper
# ==============================================================================


class QuarantineOutput(BaseModel):
    """
    Complete output from Quarantine Agent.
    This is what the Quarantine Agent produces after processing an SMS.
    """

    model_config = ConfigDict(extra="forbid", alias_generator=_to_camel, populate_by_name=True)

    request: MiddlemanRequest = Field(description="The typed request to send to Main Agent")
    response: str = Field(
        min_length=1, max_length=2000, description="Text to send back to the external person"
    )
    flags: list[str] = Field(default_factory=list, description="Optional security flags")


class MiddlemanMessage(BaseModel):
    """
    Full message sent from Quarantine system to Main Agent.
    Combines metadata with the request.
    """

    model_config = ConfigDict(extra="forbid", alias_generator=_to_camel, populate_by_name=True)

    metadata: RequestMetadata
    request: MiddlemanRequest
    quarantine_response: str = Field(description="What Quarantine plans to tell the user")
    flags: list[str] = Field(default_factory=list, description="Security flags from Quarantine")


# ==============================================================================
# Validation Functions
# ==============================================================================


def validate_request(json_data: dict) -> MiddlemanRequest:
    """
    Validate and parse a request from JSON data.

    Args:
        json_data: Dictionary containing request data

    Returns:
        Validated MiddlemanRequest instance

    Raises:
        SchemaValidationError: If validation fails
        UnknownRequestTypeError: If request type is not recognized
    """
    if not isinstance(json_data, dict):
        raise SchemaValidationError("Request must be a dictionary")

    request_type = json_data.get("type")
    if request_type is None:
        raise SchemaValidationError("Request must have a 'type' field")

    if request_type not in VALID_REQUEST_TYPES:
        raise UnknownRequestTypeError(request_type)

    # Map type to model class
    type_to_model = {
        "get_public_info": GetPublicInfoRequest,
        "check_availability": CheckAvailabilityRequest,
        "request_callback": RequestCallbackRequest,
        "request_appointment": RequestAppointmentRequest,
        "leave_message": LeaveMessageRequest,
        "relay_to_owner": RelayToOwnerRequest,
        "request_verification": RequestVerificationRequest,
        "end_conversation": EndConversationRequest,
        "cannot_process": CannotProcessRequest,
    }

    model_class = type_to_model[request_type]

    try:
        return model_class.model_validate(json_data)
    except ValidationError as e:
        raise SchemaValidationError(
            f"Invalid {request_type} request",
            errors=[
                {
                    "loc": err["loc"],
                    "msg": (
                        "Missing required field" if err.get("type") == "missing" else err["msg"]
                    ),
                }
                for err in e.errors()
            ],
        ) from e


def validate_response(json_data: dict) -> MainResponse:
    """
    Validate and parse a response from JSON data.

    Args:
        json_data: Dictionary containing response data

    Returns:
        Validated MainResponse instance

    Raises:
        SchemaValidationError: If validation fails
    """
    if not isinstance(json_data, dict):
        raise SchemaValidationError("Response must be a dictionary")

    status = json_data.get("status")
    if status is None:
        raise SchemaValidationError("Response must have a 'status' field")

    if status not in VALID_RESPONSE_STATUSES:
        raise SchemaValidationError(
            f"Unknown response status: {status}",
            errors=[{"loc": ("status",), "msg": f"'{status}' is not a valid status"}],
        )

    # Map status to model class
    status_to_model = {
        "success": SuccessResponse,
        "denied": DeniedResponse,
        "escalate": EscalateResponse,
        "verification_required": VerificationRequiredResponse,
        "end_conversation": EndConversationResponse,
    }

    model_class = status_to_model[status]

    try:
        return model_class.model_validate(json_data)
    except ValidationError as e:
        raise SchemaValidationError(
            f"Invalid {status} response",
            errors=[{"loc": err["loc"], "msg": err["msg"]} for err in e.errors()],
        ) from e


def validate_metadata(json_data: dict) -> RequestMetadata:
    """
    Validate and parse request metadata from JSON data.

    Args:
        json_data: Dictionary containing metadata

    Returns:
        Validated RequestMetadata instance

    Raises:
        SchemaValidationError: If validation fails
    """
    if not isinstance(json_data, dict):
        raise SchemaValidationError("Metadata must be a dictionary")

    try:
        return RequestMetadata.model_validate(json_data)
    except ValidationError as e:
        raise SchemaValidationError(
            "Invalid request metadata",
            errors=[{"loc": err["loc"], "msg": err["msg"]} for err in e.errors()],
        ) from e


def validate_quarantine_output(json_data: dict) -> QuarantineOutput:
    """
    Validate complete Quarantine Agent output.

    Args:
        json_data: Dictionary containing full Quarantine output

    Returns:
        Validated QuarantineOutput instance

    Raises:
        SchemaValidationError: If validation fails
    """
    if not isinstance(json_data, dict):
        raise SchemaValidationError("Quarantine output must be a dictionary")

    try:
        return QuarantineOutput.model_validate(json_data)
    except ValidationError as e:
        raise SchemaValidationError(
            "Invalid Quarantine output",
            errors=[{"loc": err["loc"], "msg": err["msg"]} for err in e.errors()],
        ) from e


def validate_full_message(json_data: dict) -> MiddlemanMessage:
    """
    Validate a full middleman message (metadata + request + response).

    Args:
        json_data: Dictionary containing full message

    Returns:
        Validated MiddlemanMessage instance

    Raises:
        SchemaValidationError: If validation fails
    """
    if not isinstance(json_data, dict):
        raise SchemaValidationError("Message must be a dictionary")

    try:
        return MiddlemanMessage.model_validate(json_data)
    except ValidationError as e:
        raise SchemaValidationError(
            "Invalid middleman message",
            errors=[{"loc": err["loc"], "msg": err["msg"]} for err in e.errors()],
        ) from e


# ==============================================================================
# Helper Functions
# ==============================================================================


def create_metadata(
    sender_phone: str,
    trust_level: TrustLevel,
    conversation_id: str | None = None,
    message_count: int = 1,
    security_flags: list[str] | None = None,
) -> RequestMetadata:
    """
    Create a new RequestMetadata instance with auto-generated fields.

    Args:
        sender_phone: E.164 phone number
        trust_level: Trust level from routing engine
        conversation_id: Optional conversation ID (generated if not provided)
        message_count: Message count in conversation
        security_flags: Optional security flags

    Returns:
        New RequestMetadata instance
    """
    return RequestMetadata(
        request_id=str(uuid.uuid4()),
        timestamp=datetime.utcnow().isoformat() + "Z",
        sender_phone=sender_phone,
        trust_level=trust_level,
        conversation_id=conversation_id or str(uuid.uuid4()),
        message_count=message_count,
        security_flags=security_flags or [],
    )


def request_to_json(request: MiddlemanRequest) -> dict:
    """Convert a request to JSON-serializable dict."""
    return request.model_dump(mode="json")


def response_to_json(response: MainResponse) -> dict:
    """Convert a response to JSON-serializable dict."""
    return response.model_dump(mode="json")
