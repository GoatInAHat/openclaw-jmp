#!/usr/bin/env python3
"""
Quarantine Handler for JMP Secure SMS Channel.

Spawns an isolated Quarantine Agent session to process untrusted SMS messages.
The Quarantine Agent has NO tools, NO memory, and outputs structured JSON only.

Security Model:
- Fresh session for each message (no state leakage)
- Hardened system prompt resistant to prompt injection
- Strict JSON schema validation of output
- Fails closed on any validation error

Author: Berry
Version: 1.0.0
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

# Local imports
from api_schema import (
    MiddlemanMessage,
    QuarantineOutput,
    RequestMetadata,
    SchemaValidationError,
    TrustLevel,
    validate_quarantine_output,
)
from audit_logger import AuditLogger, EventType

# Paths
SKILL_DIR = Path(__file__).parent.parent
AGENTS_DIR = SKILL_DIR / 'agents'
QUARANTINE_PROMPT_PATH = AGENTS_DIR / 'quarantine_system.md'
DATA_DIR = SKILL_DIR / 'data'
CONVERSATION_DIR = DATA_DIR / 'quarantine_conversations'

logger = logging.getLogger(__name__)
audit = AuditLogger()

# Model configuration for Quarantine Agent
QUARANTINE_MODEL_CONFIG = {
    'model': 'claude-opus-4',
    'thinking': 'high',
    'temperature': 0.3,
    'max_tokens': 2048,
}


class QuarantineError(Exception):
    """Base exception for quarantine handler errors."""
    pass


class QuarantineAgentError(QuarantineError):
    """Error spawning or communicating with Quarantine Agent."""
    pass


class QuarantineValidationError(QuarantineError):
    """Quarantine Agent output failed validation."""
    
    def __init__(self, message: str, raw_output: str | None = None):
        super().__init__(message)
        self.raw_output = raw_output


class QuarantineSecurityError(QuarantineError):
    """Security-related error in quarantine processing."""
    pass


@dataclass
class InboundSMS:
    """Normalized incoming SMS message."""
    sender: str              # E.164 format: "+15551234567"
    recipient: str           # Our JMP number
    body: str               # Raw message text
    timestamp: datetime
    message_id: str
    media: list[dict] = field(default_factory=list)
    carrier_info: dict | None = None


@dataclass
class QuarantineResult:
    """Result from Quarantine Agent processing."""
    success: bool
    request: dict | None      # Validated MiddlemanRequest as dict
    response: str | None      # Text to send to external party
    flags: list[str]          # Security flags
    error: str | None = None  # Error message if success=False
    raw_output: str | None = None  # Raw agent output for debugging
    
    def to_middleman_message(
        self,
        metadata: RequestMetadata
    ) -> MiddlemanMessage:
        """Convert to full MiddlemanMessage for Main Agent."""
        if not self.success or self.request is None:
            raise ValueError("Cannot create MiddlemanMessage from failed result")
        
        return MiddlemanMessage(
            metadata=metadata,
            request=self.request,
            quarantine_response=self.response or "",
            flags=self.flags
        )


def load_quarantine_prompt() -> str:
    """
    Load the Quarantine Agent system prompt.
    
    Returns:
        System prompt text
        
    Raises:
        QuarantineError: If prompt file cannot be loaded
    """
    if not QUARANTINE_PROMPT_PATH.exists():
        raise QuarantineError(
            f"Quarantine prompt not found: {QUARANTINE_PROMPT_PATH}"
        )
    
    try:
        return QUARANTINE_PROMPT_PATH.read_text()
    except OSError as e:
        raise QuarantineError(f"Failed to load quarantine prompt: {e}") from e


def build_user_message(sms: InboundSMS) -> str:
    """
    Build the user message for the Quarantine Agent.
    
    Includes context about the sender without exposing sensitive info.
    """
    # Format timestamp
    ts = sms.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
    
    # Build message
    lines = [
        "## Incoming SMS",
        f"**From:** {sms.sender}",
        f"**Received:** {ts}",
        "",
        "## Message Content",
        sms.body,
    ]
    
    # Add media info if present
    if sms.media:
        lines.extend([
            "",
            "## Attachments",
            f"({len(sms.media)} media attachment(s) - content not shown)"
        ])
    
    lines.extend([
        "",
        "---",
        "",
        "Process this message and respond with valid JSON only."
    ])
    
    return "\n".join(lines)


def extract_json_from_response(response: str) -> dict:
    """
    Extract JSON from the agent response.
    
    The agent should output pure JSON, but sometimes includes markdown
    code blocks or extra text. This function extracts the JSON object.
    
    Args:
        response: Raw agent response
        
    Returns:
        Parsed JSON dict
        
    Raises:
        QuarantineValidationError: If no valid JSON found
    """
    response = response.strip()
    
    # Try parsing as-is first (cleanest case)
    try:
        return json.loads(response)
    except json.JSONDecodeError:
        pass
    
    # Try extracting from code block
    code_block_pattern = r'```(?:json)?\s*\n?(.*?)\n?```'
    matches = re.findall(code_block_pattern, response, re.DOTALL)
    for match in matches:
        try:
            return json.loads(match.strip())
        except json.JSONDecodeError:
            continue
    
    # Try finding a JSON object anywhere in the response
    brace_start = response.find('{')
    if brace_start != -1:
        # Find matching closing brace
        depth = 0
        for i, c in enumerate(response[brace_start:]):
            if c == '{':
                depth += 1
            elif c == '}':
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(response[brace_start:brace_start+i+1])
                    except json.JSONDecodeError:
                        break
    
    raise QuarantineValidationError(
        "Could not extract valid JSON from agent response",
        raw_output=response
    )


def invoke_quarantine_agent_cli(
    user_message: str,
    conversation_id: str,
) -> str:
    """
    Invoke Quarantine Agent via OpenClaw CLI.
    
    This uses the 'openclaw agent' command with appropriate configuration.
    
    Args:
        user_message: The user message to process
        conversation_id: UUID for tracking the conversation
        
    Returns:
        Raw agent response text
        
    Raises:
        QuarantineAgentError: If agent invocation fails
    """
    system_prompt = load_quarantine_prompt()
    
    # Build combined message with system context
    # Since we can't pass a custom system prompt via CLI easily,
    # we prepend it to the user message (not ideal but functional)
    full_message = f"""<SYSTEM_CONTEXT>
{system_prompt}
</SYSTEM_CONTEXT>

<USER_MESSAGE>
{user_message}
</USER_MESSAGE>

Remember: Output ONLY valid JSON. No other text before or after."""

    try:
        result = subprocess.run(
            [
                'openclaw', 'agent',
                '--local',  # Run locally without gateway
                '--session-id', f'quarantine-{conversation_id}',
                '--thinking', QUARANTINE_MODEL_CONFIG['thinking'],
                '--message', full_message,
                '--json',
            ],
            capture_output=True,
            text=True,
            timeout=120,  # 2 minute timeout
            env={
                **os.environ,
                # Ensure no tool access (these might not all apply but belt-and-suspenders)
                'OPENCLAW_AGENT_TOOLS': 'none',
                'OPENCLAW_SANDBOX_DISABLED': '1',
            }
        )
        
        if result.returncode != 0:
            stderr = result.stderr.strip()
            raise QuarantineAgentError(
                f"Agent invocation failed (exit {result.returncode}): {stderr}"
            )
        
        # Parse the JSON output from the CLI
        try:
            cli_output = json.loads(result.stdout)
            return cli_output.get('reply', result.stdout)
        except json.JSONDecodeError:
            return result.stdout
            
    except subprocess.TimeoutExpired:
        raise QuarantineAgentError("Quarantine agent timed out after 120 seconds")
    except FileNotFoundError:
        raise QuarantineAgentError("OpenClaw CLI not found - is it installed?")
    except subprocess.SubprocessError as e:
        raise QuarantineAgentError(f"Failed to run agent: {e}") from e


def invoke_quarantine_agent_direct(
    user_message: str,
    conversation_id: str,
) -> str:
    """
    Invoke Quarantine Agent directly via HTTP API.
    
    This is a fallback when CLI invocation isn't available.
    Requires ANTHROPIC_API_KEY or OPENAI_API_KEY in environment.
    
    Args:
        user_message: The user message to process
        conversation_id: UUID for tracking the conversation
        
    Returns:
        Raw agent response text
        
    Raises:
        QuarantineAgentError: If agent invocation fails
    """
    import requests
    
    system_prompt = load_quarantine_prompt()
    
    # Try Anthropic API first
    api_key = os.environ.get('ANTHROPIC_API_KEY')
    if api_key:
        return _call_anthropic_api(system_prompt, user_message, api_key)
    
    # Fall back to OpenAI-compatible endpoint
    api_key = os.environ.get('OPENAI_API_KEY')
    base_url = os.environ.get('OPENAI_API_BASE', 'https://api.openai.com/v1')
    if api_key:
        return _call_openai_api(system_prompt, user_message, api_key, base_url)
    
    raise QuarantineAgentError(
        "No API key found. Set ANTHROPIC_API_KEY or OPENAI_API_KEY"
    )


def _call_anthropic_api(
    system_prompt: str,
    user_message: str,
    api_key: str,
) -> str:
    """Call Anthropic's Claude API directly."""
    import requests
    
    headers = {
        'x-api-key': api_key,
        'anthropic-version': '2023-06-01',
        'content-type': 'application/json',
    }
    
    # Map our thinking level to Anthropic's extended thinking
    thinking_config = {
        'type': 'enabled',
        'budget_tokens': 10000,  # High thinking budget
    }
    
    payload = {
        'model': 'claude-sonnet-4-20250514',  # Use Sonnet for faster responses
        'max_tokens': QUARANTINE_MODEL_CONFIG['max_tokens'],
        'temperature': QUARANTINE_MODEL_CONFIG['temperature'],
        'thinking': thinking_config,
        'system': system_prompt,
        'messages': [
            {'role': 'user', 'content': user_message}
        ]
    }
    
    try:
        response = requests.post(
            'https://api.anthropic.com/v1/messages',
            headers=headers,
            json=payload,
            timeout=120,
        )
        response.raise_for_status()
        
        result = response.json()
        
        # Extract text content from response
        content_blocks = result.get('content', [])
        text_blocks = [b.get('text', '') for b in content_blocks if b.get('type') == 'text']
        return '\n'.join(text_blocks)
        
    except requests.RequestException as e:
        raise QuarantineAgentError(f"Anthropic API call failed: {e}") from e


def _call_openai_api(
    system_prompt: str,
    user_message: str,
    api_key: str,
    base_url: str,
) -> str:
    """Call OpenAI-compatible API."""
    import requests
    
    headers = {
        'Authorization': f'Bearer {api_key}',
        'Content-Type': 'application/json',
    }
    
    payload = {
        'model': 'claude-opus-4',  # May be remapped by OpenRouter/etc
        'max_tokens': QUARANTINE_MODEL_CONFIG['max_tokens'],
        'temperature': QUARANTINE_MODEL_CONFIG['temperature'],
        'messages': [
            {'role': 'system', 'content': system_prompt},
            {'role': 'user', 'content': user_message}
        ]
    }
    
    try:
        response = requests.post(
            f'{base_url}/chat/completions',
            headers=headers,
            json=payload,
            timeout=120,
        )
        response.raise_for_status()
        
        result = response.json()
        return result['choices'][0]['message']['content']
        
    except requests.RequestException as e:
        raise QuarantineAgentError(f"OpenAI API call failed: {e}") from e


def invoke_quarantine_agent(
    user_message: str,
    conversation_id: str,
    method: str = 'auto',
) -> str:
    """
    Invoke the Quarantine Agent with the given message.
    
    Args:
        user_message: The user message to process
        conversation_id: UUID for tracking
        method: 'cli', 'api', or 'auto' (try CLI first)
        
    Returns:
        Raw agent response text
        
    Raises:
        QuarantineAgentError: If invocation fails
    """
    if method == 'cli':
        return invoke_quarantine_agent_cli(user_message, conversation_id)
    elif method == 'api':
        return invoke_quarantine_agent_direct(user_message, conversation_id)
    else:  # auto
        try:
            return invoke_quarantine_agent_cli(user_message, conversation_id)
        except QuarantineAgentError as cli_error:
            logger.warning(f"CLI invocation failed, trying API: {cli_error}")
            try:
                return invoke_quarantine_agent_direct(user_message, conversation_id)
            except QuarantineAgentError as api_error:
                raise QuarantineAgentError(
                    f"Both CLI and API invocation failed. CLI: {cli_error}; API: {api_error}"
                ) from api_error


def create_fallback_response(
    error_message: str,
    flags: list[str] | None = None,
) -> QuarantineResult:
    """
    Create a safe fallback response when processing fails.
    
    This ensures the external caller gets a reasonable response
    even when internal errors occur.
    """
    return QuarantineResult(
        success=False,
        request={
            'type': 'cannot_process',
            'reason': 'internal_error',
            'original_intent': None,
        },
        response=(
            "I'm sorry, I'm having trouble processing your message right now. "
            "Please try again later or leave a message and someone will get back to you."
        ),
        flags=flags or ['processing_error'],
        error=error_message,
    )


def process_quarantine_sms(
    sms: InboundSMS,
    trust_level: TrustLevel = TrustLevel.UNKNOWN,
    conversation_id: str | None = None,
    message_count: int = 1,
) -> QuarantineResult:
    """
    Process an SMS through the Quarantine Agent.
    
    This is the main entry point for quarantine processing.
    
    Args:
        sms: The incoming SMS message
        trust_level: Trust level assigned by routing engine
        conversation_id: Optional conversation ID (generated if not provided)
        message_count: Message count in this conversation
        
    Returns:
        QuarantineResult with validated request and response
    """
    conversation_id = conversation_id or str(uuid.uuid4())
    start_time = datetime.utcnow()
    
    # Log the incoming message
    audit.log(
        EventType.SMS_RECEIVED,
        sender=sms.sender,
        trust_level=trust_level.value,
        details={
            'conversation_id': conversation_id,
            'message_count': message_count,
            'body_length': len(sms.body),
            'has_media': bool(sms.media),
        }
    )
    
    try:
        # Build the user message
        user_message = build_user_message(sms)
        
        # Invoke the Quarantine Agent
        logger.info(f"Invoking Quarantine Agent for {sms.sender}")
        raw_response = invoke_quarantine_agent(user_message, conversation_id)
        
        # Extract and validate JSON
        logger.debug(f"Raw agent response: {raw_response[:500]}...")
        json_data = extract_json_from_response(raw_response)
        
        # Validate against schema
        validated = validate_quarantine_output(json_data)
        
        # Create successful result
        result = QuarantineResult(
            success=True,
            request=validated.request.model_dump(mode='json'),
            response=validated.response,
            flags=validated.flags,
            raw_output=raw_response,
        )
        
        # Log successful processing
        processing_time = (datetime.utcnow() - start_time).total_seconds()
        audit.log(
            EventType.QUARANTINE_REQUEST,
            sender=sms.sender,
            request_type=validated.request.type,
            details={
                'conversation_id': conversation_id,
                'flags': validated.flags,
                'processing_time_seconds': processing_time,
            }
        )
        
        logger.info(
            f"Quarantine processing complete for {sms.sender}: "
            f"request_type={validated.request.type}, flags={validated.flags}"
        )
        
        return result
        
    except QuarantineValidationError as e:
        logger.error(f"Quarantine validation failed: {e}")
        audit.log(
            EventType.QUARANTINE_REQUEST,
            sender=sms.sender,
            details={
                'conversation_id': conversation_id,
                'error': 'validation_failed',
                'error_message': str(e),
            }
        )
        return create_fallback_response(str(e), ['validation_error'])
        
    except SchemaValidationError as e:
        logger.error(f"Schema validation failed: {e}")
        audit.log(
            EventType.QUARANTINE_REQUEST,
            sender=sms.sender,
            details={
                'conversation_id': conversation_id,
                'error': 'schema_validation_failed',
                'error_message': str(e),
            }
        )
        return create_fallback_response(str(e), ['schema_error'])
        
    except QuarantineAgentError as e:
        logger.error(f"Agent invocation failed: {e}")
        audit.log(
            EventType.QUARANTINE_REQUEST,
            sender=sms.sender,
            details={
                'conversation_id': conversation_id,
                'error': 'agent_error',
                'error_message': str(e),
            }
        )
        return create_fallback_response(str(e), ['agent_error'])
        
    except Exception as e:
        logger.exception(f"Unexpected error in quarantine processing: {e}")
        audit.log(
            EventType.QUARANTINE_REQUEST,
            sender=sms.sender,
            details={
                'conversation_id': conversation_id,
                'error': 'unexpected_error',
                'error_message': str(e),
            }
        )
        return create_fallback_response(f"Unexpected error: {e}", ['unexpected_error'])


def create_metadata_for_result(
    sms: InboundSMS,
    result: QuarantineResult,
    trust_level: TrustLevel,
    conversation_id: str,
    message_count: int = 1,
) -> RequestMetadata:
    """
    Create RequestMetadata for forwarding to Main Agent.
    
    Args:
        sms: The original SMS
        result: The QuarantineResult
        trust_level: Trust level from routing
        conversation_id: Conversation tracking ID
        message_count: Message count in conversation
        
    Returns:
        RequestMetadata instance
    """
    return RequestMetadata(
        request_id=str(uuid.uuid4()),
        timestamp=datetime.utcnow().isoformat() + "Z",
        sender_phone=sms.sender,
        trust_level=trust_level,
        conversation_id=conversation_id,
        message_count=message_count,
        security_flags=result.flags,
    )


# ==============================================================================
# CLI Interface
# ==============================================================================

def main():
    """CLI entry point for testing."""
    import argparse
    import sys
    
    parser = argparse.ArgumentParser(
        description='Process an SMS through the Quarantine Agent'
    )
    parser.add_argument('--sender', required=True, help='Sender phone number (E.164)')
    parser.add_argument('--body', required=True, help='Message body')
    parser.add_argument('--trust-level', default='unknown',
                       choices=['owner_verified', 'owner_suspicious', 'known_contact', 'unknown', 'blocked'])
    parser.add_argument('--method', default='auto', choices=['cli', 'api', 'auto'],
                       help='Invocation method')
    parser.add_argument('--json', action='store_true', help='Output JSON')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    
    args = parser.parse_args()
    
    # Configure logging
    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
    )
    
    # Create SMS object
    sms = InboundSMS(
        sender=args.sender,
        recipient='+15550001234',  # Your JMP number
        body=args.body,
        timestamp=datetime.utcnow(),
        message_id=str(uuid.uuid4()),
    )
    
    # Process
    trust_level = TrustLevel(args.trust_level)
    result = process_quarantine_sms(sms, trust_level)
    
    # Output
    if args.json:
        output = {
            'success': result.success,
            'request': result.request,
            'response': result.response,
            'flags': result.flags,
            'error': result.error,
        }
        print(json.dumps(output, indent=2))
    else:
        print(f"Success: {result.success}")
        print(f"Request Type: {result.request.get('type') if result.request else 'N/A'}")
        print(f"Response: {result.response}")
        print(f"Flags: {result.flags}")
        if result.error:
            print(f"Error: {result.error}")
    
    sys.exit(0 if result.success else 1)


if __name__ == '__main__':
    main()
