"""
Comprehensive tests for JMP Secure SMS Channel API Schema.

These tests verify:
1. Valid requests parse correctly
2. Invalid requests are rejected
3. Requests outside the schema CANNOT be formed
4. Response validation works correctly
5. Security constraints are enforced

Run with: pytest test_api_schema.py -v
"""

import json

# Import from parent directory
import sys
import uuid
from datetime import datetime
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

from api_schema import (
    VALID_REQUEST_TYPES,
    CannotProcessRequest,
    CheckAvailabilityRequest,
    DeniedResponse,
    EndConversationReason,
    EndConversationRequest,
    EndConversationResponse,
    EscalateResponse,
    EscalationType,
    FollowUpType,
    # Request types
    GetPublicInfoRequest,
    LeaveMessageRequest,
    MessageCategory,
    MiddlemanMessage,
    PublicInfoTopic,
    QuarantineOutput,
    RelayToOwnerRequest,
    RequestAppointmentRequest,
    RequestCallbackRequest,
    RequestMetadata,
    RequestVerificationRequest,
    # Exceptions
    SchemaValidationError,
    # Response types
    SuccessResponse,
    # Enums
    TrustLevel,
    UnknownRequestTypeError,
    Urgency,
    VerificationPurpose,
    VerificationRequiredResponse,
    create_metadata,
    request_to_json,
    response_to_json,
    validate_full_message,
    validate_metadata,
    validate_quarantine_output,
    # Validation functions
    validate_request,
    validate_response,
)

# ==============================================================================
# Fixtures
# ==============================================================================


@pytest.fixture
def valid_uuid():
    return str(uuid.uuid4())


@pytest.fixture
def valid_timestamp():
    return datetime.utcnow().isoformat() + "Z"


@pytest.fixture
def valid_phone():
    return "+15551234567"


@pytest.fixture
def valid_metadata(valid_uuid, valid_timestamp, valid_phone):
    return {
        "request_id": valid_uuid,
        "timestamp": valid_timestamp,
        "sender_phone": valid_phone,
        "trust_level": "unknown",
        "conversation_id": valid_uuid,
        "message_count": 1,
        "security_flags": [],
    }


# ==============================================================================
# Test: Valid Request Parsing
# ==============================================================================


class TestValidRequests:
    """Test that all valid request types parse correctly."""

    def test_get_public_info(self):
        """Test get_public_info request."""
        for topic in PublicInfoTopic:
            request = validate_request(
                {
                    "type": "get_public_info",
                    "topic": topic.value,
                }
            )
            assert isinstance(request, GetPublicInfoRequest)
            assert request.type == "get_public_info"
            assert request.topic == topic

    def test_check_availability(self):
        """Test check_availability request."""
        request = validate_request(
            {
                "type": "check_availability",
                "date_range_start": "2026-02-15",
                "date_range_end": "2026-02-20",
                "purpose": "scheduling a meeting",
            }
        )
        assert isinstance(request, CheckAvailabilityRequest)
        assert request.date_range_start == "2026-02-15"
        assert request.purpose == "scheduling a meeting"

    def test_check_availability_without_purpose(self):
        """Test check_availability with optional purpose omitted."""
        request = validate_request(
            {
                "type": "check_availability",
                "date_range_start": "2026-02-15",
                "date_range_end": "2026-02-20",
            }
        )
        assert request.purpose is None

    def test_request_callback(self):
        """Test request_callback request."""
        request = validate_request(
            {
                "type": "request_callback",
                "topic": "Discuss project",
                "urgency": "high",
                "preferred_time": "afternoon",
            }
        )
        assert isinstance(request, RequestCallbackRequest)
        assert request.urgency == Urgency.HIGH

    def test_request_callback_default_urgency(self):
        """Test request_callback with default urgency."""
        request = validate_request(
            {
                "type": "request_callback",
                "topic": "Discuss project",
            }
        )
        assert request.urgency == Urgency.NORMAL

    def test_request_appointment(self):
        """Test request_appointment request."""
        request = validate_request(
            {
                "type": "request_appointment",
                "purpose": "product demo",
                "preferred_date": "2026-02-18",
                "preferred_time": "2:00 PM",
                "duration": 30,
            }
        )
        assert isinstance(request, RequestAppointmentRequest)
        assert request.duration == 30

    def test_leave_message(self):
        """Test leave_message request."""
        request = validate_request(
            {
                "type": "leave_message",
                "message": "Please call me back",
                "sender_name": "John Doe",
                "callback_requested": True,
            }
        )
        assert isinstance(request, LeaveMessageRequest)
        assert request.callback_requested is True

    def test_relay_to_owner(self):
        """Test relay_to_owner request."""
        request = validate_request(
            {
                "type": "relay_to_owner",
                "summary": "Customer has billing question",
                "category": "question",
                "suggested_action": "Check account status",
            }
        )
        assert isinstance(request, RelayToOwnerRequest)
        assert request.category == MessageCategory.QUESTION

    def test_request_verification(self):
        """Test request_verification request."""
        request = validate_request(
            {
                "type": "request_verification",
                "purpose": "become_known_contact",
            }
        )
        assert isinstance(request, RequestVerificationRequest)
        assert request.purpose == VerificationPurpose.BECOME_KNOWN_CONTACT

    def test_end_conversation(self):
        """Test end_conversation request."""
        for reason in EndConversationReason:
            request = validate_request(
                {
                    "type": "end_conversation",
                    "reason": reason.value,
                }
            )
            assert isinstance(request, EndConversationRequest)
            assert request.reason == reason

    def test_cannot_process(self):
        """Test cannot_process request."""
        request = validate_request(
            {
                "type": "cannot_process",
                "reason": "Request requires private data",
                "original_intent": "User asked for password",
            }
        )
        assert isinstance(request, CannotProcessRequest)


# ==============================================================================
# Test: Invalid Request Rejection
# ==============================================================================


class TestInvalidRequests:
    """Test that invalid requests are properly rejected."""

    def test_missing_type(self):
        """Request without type field is rejected."""
        with pytest.raises(SchemaValidationError) as exc:
            validate_request({"topic": "business_hours"})
        assert "type" in str(exc.value)

    def test_unknown_type(self):
        """Unknown request type is rejected with specific error."""
        with pytest.raises(UnknownRequestTypeError) as exc:
            validate_request({"type": "hack_the_system"})
        assert exc.value.request_type == "hack_the_system"

    def test_extra_fields_rejected(self):
        """Extra/unknown fields are rejected."""
        with pytest.raises(SchemaValidationError):
            validate_request(
                {
                    "type": "get_public_info",
                    "topic": "business_hours",
                    "secret_field": "malicious_data",
                }
            )

    def test_invalid_enum_value(self):
        """Invalid enum values are rejected."""
        with pytest.raises(SchemaValidationError):
            validate_request(
                {
                    "type": "get_public_info",
                    "topic": "private_secrets",
                }
            )

    def test_missing_required_field(self):
        """Missing required fields are rejected."""
        with pytest.raises(SchemaValidationError):
            validate_request(
                {
                    "type": "leave_message",
                    # missing "message" field
                }
            )

    def test_invalid_date_format(self):
        """Invalid date formats are rejected."""
        with pytest.raises(SchemaValidationError):
            validate_request(
                {
                    "type": "check_availability",
                    "date_range_start": "not-a-date",
                    "date_range_end": "2026-02-20",
                }
            )

    def test_date_range_invalid_order(self):
        """Start after end is rejected."""
        with pytest.raises(SchemaValidationError):
            validate_request(
                {
                    "type": "check_availability",
                    "date_range_start": "2026-02-25",
                    "date_range_end": "2026-02-20",
                }
            )

    def test_string_too_long(self):
        """Strings exceeding max length are rejected."""
        with pytest.raises(SchemaValidationError):
            validate_request(
                {
                    "type": "leave_message",
                    "message": "x" * 3000,  # Exceeds 2000 char limit
                    "callback_requested": False,
                }
            )

    def test_negative_duration(self):
        """Negative duration is rejected."""
        with pytest.raises(SchemaValidationError):
            validate_request(
                {
                    "type": "request_appointment",
                    "purpose": "meeting",
                    "preferred_date": "2026-02-20",
                    "duration": -10,
                }
            )

    def test_duration_too_long(self):
        """Duration over 8 hours is rejected."""
        with pytest.raises(SchemaValidationError):
            validate_request(
                {
                    "type": "request_appointment",
                    "purpose": "meeting",
                    "preferred_date": "2026-02-20",
                    "duration": 600,  # 10 hours
                }
            )

    def test_empty_message(self):
        """Empty message is rejected."""
        with pytest.raises(SchemaValidationError):
            validate_request(
                {
                    "type": "leave_message",
                    "message": "",
                    "callback_requested": False,
                }
            )

    def test_non_dict_input(self):
        """Non-dictionary input is rejected."""
        with pytest.raises(SchemaValidationError):
            validate_request("not a dict")

        with pytest.raises(SchemaValidationError):
            validate_request(["list", "of", "things"])

    def test_null_required_field(self):
        """Null value for required field is rejected."""
        with pytest.raises(SchemaValidationError):
            validate_request(
                {
                    "type": "leave_message",
                    "message": None,
                    "callback_requested": False,
                }
            )


# ==============================================================================
# Test: Schema Boundary Enforcement
# ==============================================================================


class TestSchemaBoundary:
    """Test that requests outside the schema CANNOT be formed."""

    def test_all_valid_types_are_known(self):
        """Verify the set of valid types is complete and frozen."""
        assert VALID_REQUEST_TYPES == frozenset(
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

    def test_cannot_request_sensitive_operations(self):
        """Verify sensitive operations cannot be requested."""
        sensitive_types = [
            "get_credentials",
            "access_memory",
            "execute_command",
            "read_file",
            "send_email",
            "transfer_money",
            "delete_data",
            "change_password",
            "get_private_info",
            "access_calendar",
            "read_messages",
        ]

        for bad_type in sensitive_types:
            with pytest.raises(UnknownRequestTypeError):
                validate_request({"type": bad_type})

    def test_cannot_inject_fields(self):
        """Verify extra fields cannot be injected."""
        # Try to inject a "command" field
        with pytest.raises(SchemaValidationError):
            validate_request(
                {
                    "type": "leave_message",
                    "message": "normal message",
                    "callback_requested": False,
                    "command": "rm -rf /",
                }
            )

    def test_frozen_models(self):
        """Verify request models are immutable (frozen)."""
        request = validate_request(
            {
                "type": "get_public_info",
                "topic": "business_hours",
            }
        )

        with pytest.raises(Exception):  # Pydantic raises various errors for frozen
            request.topic = "location"

    def test_type_field_immutable(self):
        """Verify type field cannot be changed after creation."""
        request = validate_request(
            {
                "type": "get_public_info",
                "topic": "business_hours",
            }
        )

        with pytest.raises(Exception):
            request.type = "execute_command"


# ==============================================================================
# Test: Response Validation
# ==============================================================================


class TestResponseValidation:
    """Test response validation."""

    def test_success_response(self):
        """Test valid success response."""
        response = validate_response(
            {
                "status": "success",
                "public_message": "Your request has been processed.",
                "internal_note": "User requested business hours",
            }
        )
        assert isinstance(response, SuccessResponse)
        assert response.status == "success"

    def test_denied_response(self):
        """Test valid denied response."""
        response = validate_response(
            {
                "status": "denied",
                "reason": "Blocked number",
                "public_message": "This number has been blocked.",
            }
        )
        assert isinstance(response, DeniedResponse)

    def test_escalate_response(self):
        """Test valid escalate response."""
        response = validate_response(
            {
                "status": "escalate",
                "reason": "Complex request needs owner review",
                "escalation_type": "owner_review",
                "public_message": "Your request has been forwarded.",
            }
        )
        assert isinstance(response, EscalateResponse)
        assert response.escalation_type == EscalationType.OWNER_REVIEW

    def test_verification_required_response(self, valid_uuid):
        """Test valid verification_required response."""
        response = validate_response(
            {
                "status": "verification_required",
                "verification_type": "sms_code",
                "public_message": "Please enter the code we sent.",
                "verification_id": valid_uuid,
            }
        )
        assert isinstance(response, VerificationRequiredResponse)

    def test_end_conversation_response(self):
        """Test valid end_conversation response."""
        response = validate_response(
            {
                "status": "end_conversation",
                "public_message": "Goodbye!",
                "follow_up": {
                    "type": "owner_will_contact",
                    "timeframe": "within 24 hours",
                },
            }
        )
        assert isinstance(response, EndConversationResponse)
        assert response.follow_up.type == FollowUpType.OWNER_WILL_CONTACT

    def test_invalid_status(self):
        """Invalid status is rejected."""
        with pytest.raises(SchemaValidationError):
            validate_response(
                {
                    "status": "hacked",
                    "data": "malicious",
                }
            )

    def test_missing_public_message(self):
        """Missing public_message is rejected."""
        with pytest.raises(SchemaValidationError):
            validate_response(
                {
                    "status": "success",
                    # missing public_message
                }
            )

    def test_invalid_verification_id(self):
        """Invalid UUID for verification_id is rejected."""
        with pytest.raises(SchemaValidationError):
            validate_response(
                {
                    "status": "verification_required",
                    "verification_type": "sms_code",
                    "public_message": "Enter code",
                    "verification_id": "not-a-uuid",
                }
            )


# ==============================================================================
# Test: Metadata Validation
# ==============================================================================


class TestMetadataValidation:
    """Test request metadata validation."""

    def test_valid_metadata(self, valid_metadata):
        """Valid metadata parses correctly."""
        metadata = validate_metadata(valid_metadata)
        assert isinstance(metadata, RequestMetadata)
        assert metadata.trust_level == TrustLevel.UNKNOWN

    def test_all_trust_levels(self, valid_metadata):
        """All trust levels are valid."""
        for level in TrustLevel:
            data = valid_metadata.copy()
            data["trust_level"] = level.value
            metadata = validate_metadata(data)
            assert metadata.trust_level == level

    def test_invalid_request_id(self, valid_metadata):
        """Invalid UUID for request_id is rejected."""
        data = valid_metadata.copy()
        data["request_id"] = "not-a-uuid"
        with pytest.raises(SchemaValidationError):
            validate_metadata(data)

    def test_invalid_phone_format(self, valid_metadata):
        """Invalid phone format is rejected."""
        invalid_phones = [
            "5551234567",  # No +
            "555-123-4567",  # Dashes, no +
            "(555) 123-4567",  # Parentheses
            "+1-555-123-4567",  # Dashes with + (not valid E.164)
            "phone",  # Not a number
            "",  # Empty
            "+",  # Just plus
            "+0123456789",  # Starts with 0 (invalid)
        ]

        for bad_phone in invalid_phones:
            data = valid_metadata.copy()
            data["sender_phone"] = bad_phone
            with pytest.raises(SchemaValidationError):
                validate_metadata(data)

    def test_valid_e164_phones(self, valid_metadata):
        """Valid E.164 phones are accepted."""
        valid_phones = [
            "+15551234567",  # US
            "+447911123456",  # UK
            "+33612345678",  # France
            "+81312345678",  # Japan
            "+12",  # Minimal valid (2 digits)
            "+861234567890",  # China
        ]

        for phone in valid_phones:
            data = valid_metadata.copy()
            data["sender_phone"] = phone
            metadata = validate_metadata(data)
            assert metadata.sender_phone == phone

    def test_invalid_timestamp(self, valid_metadata):
        """Invalid timestamp is rejected."""
        data = valid_metadata.copy()
        data["timestamp"] = "not-a-timestamp"
        with pytest.raises(SchemaValidationError):
            validate_metadata(data)

    def test_message_count_minimum(self, valid_metadata):
        """Message count must be at least 1."""
        data = valid_metadata.copy()
        data["message_count"] = 0
        with pytest.raises(SchemaValidationError):
            validate_metadata(data)

    def test_security_flags(self, valid_metadata):
        """Security flags are properly stored."""
        data = valid_metadata.copy()
        data["security_flags"] = ["credential_request", "possible_phishing"]
        metadata = validate_metadata(data)
        assert "credential_request" in metadata.security_flags


# ==============================================================================
# Test: Full Message Validation
# ==============================================================================


class TestFullMessageValidation:
    """Test complete message validation."""

    def test_valid_full_message(self, valid_metadata):
        """Valid full message parses correctly."""
        message = validate_full_message(
            {
                "metadata": valid_metadata,
                "request": {
                    "type": "leave_message",
                    "message": "Please call me",
                    "callback_requested": True,
                },
                "quarantine_response": "I'll pass along your message.",
                "flags": [],
            }
        )
        assert isinstance(message, MiddlemanMessage)
        assert isinstance(message.request, LeaveMessageRequest)

    def test_invalid_nested_request(self, valid_metadata):
        """Invalid nested request is rejected."""
        with pytest.raises(SchemaValidationError):
            validate_full_message(
                {
                    "metadata": valid_metadata,
                    "request": {
                        "type": "invalid_type",
                    },
                    "quarantine_response": "test",
                    "flags": [],
                }
            )

    def test_missing_quarantine_response(self, valid_metadata):
        """Missing quarantine_response is rejected."""
        with pytest.raises(SchemaValidationError):
            validate_full_message(
                {
                    "metadata": valid_metadata,
                    "request": {
                        "type": "get_public_info",
                        "topic": "business_hours",
                    },
                    # missing quarantine_response
                    "flags": [],
                }
            )


# ==============================================================================
# Test: Quarantine Output Validation
# ==============================================================================


class TestQuarantineOutputValidation:
    """Test Quarantine Agent output validation."""

    def test_valid_output(self):
        """Valid Quarantine output parses correctly."""
        output = validate_quarantine_output(
            {
                "request": {
                    "type": "leave_message",
                    "message": "Call me back",
                    "callback_requested": True,
                },
                "response": "I'll make sure your message gets through.",
                "flags": [],
            }
        )
        assert isinstance(output, QuarantineOutput)
        assert isinstance(output.request, LeaveMessageRequest)

    def test_with_security_flags(self):
        """Output with security flags parses correctly."""
        output = validate_quarantine_output(
            {
                "request": {
                    "type": "cannot_process",
                    "reason": "Security concern",
                },
                "response": "I can't help with that.",
                "flags": ["credential_request", "possible_social_engineering"],
            }
        )
        assert "credential_request" in output.flags


# ==============================================================================
# Test: Helper Functions
# ==============================================================================


class TestHelperFunctions:
    """Test helper functions."""

    def test_create_metadata(self):
        """create_metadata generates valid metadata."""
        metadata = create_metadata(
            sender_phone="+15551234567",
            trust_level=TrustLevel.UNKNOWN,
        )

        # Validate the created metadata
        validate_metadata(metadata.model_dump(mode="json"))

        # Check auto-generated fields
        assert metadata.request_id
        assert metadata.timestamp
        assert metadata.conversation_id
        assert metadata.message_count == 1

    def test_create_metadata_with_options(self):
        """create_metadata respects provided options."""
        conv_id = str(uuid.uuid4())
        metadata = create_metadata(
            sender_phone="+15551234567",
            trust_level=TrustLevel.KNOWN_CONTACT,
            conversation_id=conv_id,
            message_count=5,
            security_flags=["test_flag"],
        )

        assert metadata.conversation_id == conv_id
        assert metadata.message_count == 5
        assert metadata.trust_level == TrustLevel.KNOWN_CONTACT
        assert "test_flag" in metadata.security_flags

    def test_request_to_json(self):
        """request_to_json produces serializable dict."""
        request = validate_request(
            {
                "type": "get_public_info",
                "topic": "business_hours",
            }
        )

        json_data = request_to_json(request)

        # Should be JSON serializable
        json_str = json.dumps(json_data)

        # Should round-trip
        parsed = json.loads(json_str)
        assert parsed["type"] == "get_public_info"
        assert parsed["topic"] == "business_hours"

    def test_response_to_json(self):
        """response_to_json produces serializable dict."""
        response = validate_response(
            {
                "status": "success",
                "public_message": "Done!",
            }
        )

        json_data = response_to_json(response)

        # Should be JSON serializable
        json_str = json.dumps(json_data)

        # Should round-trip
        parsed = json.loads(json_str)
        assert parsed["status"] == "success"


# ==============================================================================
# Test: Security Constraints
# ==============================================================================


class TestSecurityConstraints:
    """Test security-related constraints."""

    def test_no_tool_invocation_possible(self):
        """Verify no request type can invoke tools."""
        # Check that none of the request types have fields that could
        # be interpreted as tool invocations
        dangerous_field_names = [
            "command",
            "tool",
            "execute",
            "run",
            "invoke",
            "code",
            "script",
            "function",
            "eval",
            "shell",
        ]

        for request_type in VALID_REQUEST_TYPES:
            # Get the model class
            if request_type == "get_public_info":
                model = GetPublicInfoRequest
            elif request_type == "check_availability":
                model = CheckAvailabilityRequest
            elif request_type == "request_callback":
                model = RequestCallbackRequest
            elif request_type == "request_appointment":
                model = RequestAppointmentRequest
            elif request_type == "leave_message":
                model = LeaveMessageRequest
            elif request_type == "relay_to_owner":
                model = RelayToOwnerRequest
            elif request_type == "request_verification":
                model = RequestVerificationRequest
            elif request_type == "end_conversation":
                model = EndConversationRequest
            elif request_type == "cannot_process":
                model = CannotProcessRequest

            # Check field names
            for field_name in model.model_fields.keys():
                assert field_name not in dangerous_field_names, (
                    f"Dangerous field '{field_name}' found in {request_type}"
                )

    def test_no_sensitive_data_in_responses(self):
        """Verify response types don't expose internal data."""
        # Success response internal_note should be marked as internal
        response = validate_response(
            {
                "status": "success",
                "public_message": "All good",
                "internal_note": "SECRET DATA HERE",
            }
        )

        # The response model should only send public_message
        assert response.public_message == "All good"
        assert response.internal_note == "SECRET DATA HERE"

        # When serialized for sending, internal_note should be stripped
        # (this would be done by the handler, not the schema)

    def test_length_limits_prevent_data_exfil(self):
        """Verify length limits prevent large data exfiltration."""
        # Try to exfiltrate via message field
        with pytest.raises(SchemaValidationError):
            validate_request(
                {
                    "type": "leave_message",
                    "message": "x" * 10000,  # 10KB
                    "callback_requested": False,
                }
            )

        # 2000 chars is the limit
        request = validate_request(
            {
                "type": "leave_message",
                "message": "x" * 2000,
                "callback_requested": False,
            }
        )
        assert len(request.message) == 2000


# ==============================================================================
# Test: Request Handler Integration
# ==============================================================================


class TestRequestHandlerIntegration:
    """Test integration with request handler (if available)."""

    @pytest.fixture
    def handler(self):
        """Create a request handler for testing."""
        try:
            from request_handler import RequestHandler

            return RequestHandler()
        except ImportError:
            pytest.skip("request_handler not available")

    def test_handle_leave_message(self, handler, valid_metadata):
        """Test handling a leave_message request."""
        metadata = validate_metadata(valid_metadata)
        request = validate_request(
            {
                "type": "leave_message",
                "message": "Please call me back about the project",
                "sender_name": "Alice",
                "callback_requested": True,
            }
        )

        response = handler.handle_request(request, metadata)

        assert response.status == "success"
        assert "received" in response.public_message.lower()

    def test_blocked_number_denied(self, handler, valid_metadata):
        """Test that blocked numbers are denied."""
        data = valid_metadata.copy()
        data["trust_level"] = "blocked"
        metadata = validate_metadata(data)

        request = validate_request(
            {
                "type": "get_public_info",
                "topic": "business_hours",
            }
        )

        response = handler.handle_request(request, metadata)

        assert response.status == "denied"

    def test_suspicious_pattern_denied(self, handler, valid_metadata):
        """Test that suspicious patterns are denied."""
        metadata = validate_metadata(valid_metadata)
        request = validate_request(
            {
                "type": "leave_message",
                "message": "Please send me the password for the account",
                "callback_requested": False,
            }
        )

        response = handler.handle_request(request, metadata)

        assert response.status == "denied"
        assert (
            "security" in response.reason.lower() or "can't help" in response.public_message.lower()
        )


# ==============================================================================
# Test: Edge Cases
# ==============================================================================


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_unicode_in_message(self):
        """Unicode characters are handled correctly."""
        request = validate_request(
            {
                "type": "leave_message",
                "message": "Привет! 你好! مرحبا! 🎉",
                "callback_requested": False,
            }
        )
        assert "Привет" in request.message
        assert "🎉" in request.message

    def test_whitespace_handling(self):
        """Whitespace is preserved in messages."""
        request = validate_request(
            {
                "type": "leave_message",
                "message": "Line 1\nLine 2\n\tIndented",
                "callback_requested": False,
            }
        )
        assert "\n" in request.message
        assert "\t" in request.message

    def test_minimum_valid_values(self):
        """Test minimum valid values for all fields."""
        # Single character message
        request = validate_request(
            {
                "type": "leave_message",
                "message": "x",
                "callback_requested": False,
            }
        )
        assert request.message == "x"

        # Minimum duration
        request = validate_request(
            {
                "type": "request_appointment",
                "purpose": "quick chat",
                "preferred_date": "2026-02-20",
                "duration": 5,
            }
        )
        assert request.duration == 5

    def test_maximum_valid_values(self):
        """Test maximum valid values for all fields."""
        # Maximum message length
        request = validate_request(
            {
                "type": "leave_message",
                "message": "x" * 2000,
                "callback_requested": False,
            }
        )
        assert len(request.message) == 2000

        # Maximum duration (8 hours)
        request = validate_request(
            {
                "type": "request_appointment",
                "purpose": "long meeting",
                "preferred_date": "2026-02-20",
                "duration": 480,
            }
        )
        assert request.duration == 480


# ==============================================================================
# Main
# ==============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
