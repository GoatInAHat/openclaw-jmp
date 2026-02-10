"""
JMP Secure SMS Channel - Scripts Package

This package contains the core implementation for the JMP secure SMS channel:
- api_schema.py: Typed API schema (security boundary)
- request_handler.py: Main Agent request handler
"""

from .api_schema import (
    # Request types
    MiddlemanRequest,
    GetPublicInfoRequest,
    CheckAvailabilityRequest,
    RequestCallbackRequest,
    RequestAppointmentRequest,
    LeaveMessageRequest,
    RelayToOwnerRequest,
    RequestVerificationRequest,
    EndConversationRequest,
    CannotProcessRequest,
    # Response types
    MainResponse,
    SuccessResponse,
    DeniedResponse,
    EscalateResponse,
    VerificationRequiredResponse,
    EndConversationResponse,
    # Other types
    RequestMetadata,
    MiddlemanMessage,
    QuarantineOutput,
    TrustLevel,
    # Validation
    validate_request,
    validate_response,
    validate_metadata,
    validate_full_message,
    validate_quarantine_output,
    create_metadata,
    # Exceptions
    SchemaValidationError,
    UnknownRequestTypeError,
    SecurityViolationError,
)

__all__ = [
    # Request types
    "MiddlemanRequest",
    "GetPublicInfoRequest",
    "CheckAvailabilityRequest",
    "RequestCallbackRequest",
    "RequestAppointmentRequest",
    "LeaveMessageRequest",
    "RelayToOwnerRequest",
    "RequestVerificationRequest",
    "EndConversationRequest",
    "CannotProcessRequest",
    # Response types
    "MainResponse",
    "SuccessResponse",
    "DeniedResponse",
    "EscalateResponse",
    "VerificationRequiredResponse",
    "EndConversationResponse",
    # Other types
    "RequestMetadata",
    "MiddlemanMessage",
    "QuarantineOutput",
    "TrustLevel",
    # Validation
    "validate_request",
    "validate_response",
    "validate_metadata",
    "validate_full_message",
    "validate_quarantine_output",
    "create_metadata",
    # Exceptions
    "SchemaValidationError",
    "UnknownRequestTypeError",
    "SecurityViolationError",
]
