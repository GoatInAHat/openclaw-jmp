"""
JMP Secure SMS Channel - Scripts Package

This package contains the core implementation for the JMP secure SMS channel:
- api_schema.py: Typed API schema (security boundary)
- request_handler.py: Main Agent request handler
"""

from .api_schema import (
    CannotProcessRequest,
    CheckAvailabilityRequest,
    DeniedResponse,
    EndConversationRequest,
    EndConversationResponse,
    EscalateResponse,
    GetPublicInfoRequest,
    LeaveMessageRequest,
    # Response types
    MainResponse,
    MiddlemanMessage,
    # Request types
    MiddlemanRequest,
    QuarantineOutput,
    RelayToOwnerRequest,
    RequestAppointmentRequest,
    RequestCallbackRequest,
    # Other types
    RequestMetadata,
    RequestVerificationRequest,
    # Exceptions
    SchemaValidationError,
    SecurityViolationError,
    SuccessResponse,
    TrustLevel,
    UnknownRequestTypeError,
    VerificationRequiredResponse,
    create_metadata,
    validate_full_message,
    validate_metadata,
    validate_quarantine_output,
    # Validation
    validate_request,
    validate_response,
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
