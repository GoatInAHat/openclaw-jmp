#!/usr/bin/env python3
"""
Comprehensive audit logging for JMP SMS security.

Logs all SMS interactions, routing decisions, and security events
in JSONL format for easy analysis and 90-day retention.
"""

import asyncio
import gzip
import json
import logging
import threading
from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path

try:
    from .paths import AUDIT_DIR
except ImportError:  # Direct script execution
    from paths import AUDIT_DIR

logger = logging.getLogger(__name__)


class AuditEventType(str, Enum):
    """Types of audit events."""

    SMS_RECEIVED = "sms_received"
    SMS_SENT = "sms_sent"
    ROUTING_DECISION = "routing_decision"
    QUARANTINE_REQUEST = "quarantine_request"
    QUARANTINE_RESPONSE = "quarantine_response"
    MAIN_REQUEST = "main_request"
    MAIN_RESPONSE = "main_response"
    VERIFICATION_START = "verification_start"
    VERIFICATION_COMPLETE = "verification_complete"
    VERIFICATION_FAILED = "verification_failed"
    SPOOF_DETECTED = "spoof_detected"
    SPOOF_CHALLENGE_SENT = "spoof_challenge_sent"
    SPOOF_CHALLENGE_RESPONSE = "spoof_challenge_response"
    RATE_LIMIT_HIT = "rate_limit_hit"
    BLOCKED = "blocked"
    ERROR = "error"
    SECURITY_ALERT = "security_alert"
    DAEMON_START = "daemon_start"
    DAEMON_STOP = "daemon_stop"
    ESCALATION = "escalation"


@dataclass
class AuditEvent:
    """Represents an audit log event."""

    timestamp: str
    event_type: str
    session_id: str | None = None
    conversation_id: str | None = None
    sender: str | None = None
    recipient: str | None = None
    trust_level: str | None = None
    request_type: str | None = None
    spoof_indicators: list | None = None
    message_preview: str | None = None  # First 50 chars only
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert to dictionary, excluding None values."""
        d = asdict(self)
        return {k: v for k, v in d.items() if v is not None}

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict())


class AuditLogger:
    """
    Audit logger with async file I/O and automatic rotation.

    Features:
    - JSONL format for easy analysis
    - Automatic daily rotation
    - 90-day retention with cleanup
    - Buffered writes for performance
    - Thread-safe for concurrent message processing
    """

    DEFAULT_LOG_DIR = AUDIT_DIR
    RETENTION_DAYS = 90
    BUFFER_SIZE = 100
    FLUSH_INTERVAL_SECONDS = 5

    def __init__(
        self,
        log_dir: Path | None = None,
        retention_days: int = RETENTION_DAYS,
        buffer_size: int = BUFFER_SIZE,
        compress_old: bool = True,
    ):
        self.log_dir = log_dir or self.DEFAULT_LOG_DIR
        self.retention_days = retention_days
        self.buffer_size = buffer_size
        self.compress_old = compress_old

        # Thread-safe buffer
        self._buffer: deque = deque(maxlen=buffer_size * 2)
        self._lock = threading.Lock()
        self._current_date: str | None = None
        self._current_file: Path | None = None
        self._flush_task: asyncio.Task | None = None
        self._running = False

        # Ensure log directory exists
        self.log_dir.mkdir(parents=True, exist_ok=True)

    def _get_log_file(self, date: datetime | None = None) -> Path:
        """Get the log file path for a given date."""
        if date is None:
            date = datetime.utcnow()
        date_str = date.strftime("%Y-%m-%d")
        return self.log_dir / f"audit-{date_str}.jsonl"

    def _make_event(self, event_type: AuditEventType, **kwargs) -> AuditEvent:
        """Create an audit event with timestamp."""
        return AuditEvent(
            timestamp=datetime.utcnow().isoformat() + "Z", event_type=event_type.value, **kwargs
        )

    def log(self, event_type: AuditEventType, **kwargs) -> None:
        """
        Log an audit event (thread-safe).

        Event is buffered and flushed periodically or when buffer is full.
        """
        event = self._make_event(event_type, **kwargs)

        with self._lock:
            self._buffer.append(event)

            # Force flush if buffer is getting full
            if len(self._buffer) >= self.buffer_size:
                self._sync_flush()

    def log_sms_received(
        self, sender: str, body: str, conversation_id: str | None = None, **extra
    ) -> None:
        """Log an incoming SMS message."""
        self.log(
            AuditEventType.SMS_RECEIVED,
            sender=sender,
            message_preview=body[:50] if body else None,
            conversation_id=conversation_id,
            details=extra,
        )

    def log_sms_sent(
        self, recipient: str, body: str, conversation_id: str | None = None, **extra
    ) -> None:
        """Log an outgoing SMS message."""
        self.log(
            AuditEventType.SMS_SENT,
            recipient=recipient,
            message_preview=body[:50] if body else None,
            conversation_id=conversation_id,
            details=extra,
        )

    def log_routing_decision(
        self,
        sender: str,
        trust_level: str,
        action: str,
        spoof_indicators: list | None = None,
        **extra,
    ) -> None:
        """Log a routing decision."""
        self.log(
            AuditEventType.ROUTING_DECISION,
            sender=sender,
            trust_level=trust_level,
            spoof_indicators=spoof_indicators,
            details={"action": action, **extra},
        )

    def log_quarantine_interaction(
        self, sender: str, request_type: str, response: str, flags: list | None = None, **extra
    ) -> None:
        """Log a quarantine agent interaction."""
        self.log(
            AuditEventType.QUARANTINE_REQUEST,
            sender=sender,
            request_type=request_type,
            message_preview=response[:50] if response else None,
            details={"flags": flags, **extra},
        )

    def log_main_request(
        self, sender: str, request_type: str, conversation_id: str | None = None, **extra
    ) -> None:
        """Log a request sent to main agent."""
        self.log(
            AuditEventType.MAIN_REQUEST,
            sender=sender,
            request_type=request_type,
            conversation_id=conversation_id,
            details=extra,
        )

    def log_main_response(
        self, sender: str, status: str, conversation_id: str | None = None, **extra
    ) -> None:
        """Log main agent's response."""
        self.log(
            AuditEventType.MAIN_RESPONSE,
            sender=sender,
            conversation_id=conversation_id,
            details={"status": status, **extra},
        )

    def log_spoof_detected(self, sender: str, indicators: list, action_taken: str, **extra) -> None:
        """Log a spoof detection event."""
        self.log(
            AuditEventType.SPOOF_DETECTED,
            sender=sender,
            spoof_indicators=indicators,
            details={"action_taken": action_taken, **extra},
        )

    def log_rate_limit(
        self, sender: str, limit_type: str, current_count: int, limit: int, **extra
    ) -> None:
        """Log a rate limit event."""
        self.log(
            AuditEventType.RATE_LIMIT_HIT,
            sender=sender,
            details={
                "limit_type": limit_type,
                "current_count": current_count,
                "limit": limit,
                **extra,
            },
        )

    def log_security_alert(
        self,
        alert_type: str,
        sender: str | None = None,
        description: str = "",
        severity: str = "medium",
        **extra,
    ) -> None:
        """Log a security alert."""
        self.log(
            AuditEventType.SECURITY_ALERT,
            sender=sender,
            details={
                "alert_type": alert_type,
                "description": description,
                "severity": severity,
                **extra,
            },
        )

    def log_escalation(
        self,
        sender: str,
        reason: str,
        escalation_type: str,
        conversation_id: str | None = None,
        **extra,
    ) -> None:
        """Log an escalation to owner."""
        self.log(
            AuditEventType.ESCALATION,
            sender=sender,
            conversation_id=conversation_id,
            details={"reason": reason, "escalation_type": escalation_type, **extra},
        )

    def log_error(
        self, error_type: str, error_message: str, sender: str | None = None, **extra
    ) -> None:
        """Log an error event."""
        self.log(
            AuditEventType.ERROR,
            sender=sender,
            details={"error_type": error_type, "error_message": error_message, **extra},
        )

    def _sync_flush(self) -> None:
        """Synchronously flush buffer to disk (must hold lock)."""
        if not self._buffer:
            return

        log_file = self._get_log_file()

        try:
            events = list(self._buffer)
            self._buffer.clear()

            with open(log_file, "a") as f:
                for event in events:
                    f.write(event.to_json() + "\n")

        except Exception as e:
            logger.error(f"Failed to flush audit log: {e}")
            # Re-add events to buffer on failure
            for event in events:
                self._buffer.appendleft(event)

    async def flush(self) -> None:
        """Async flush buffer to disk."""
        with self._lock:
            self._sync_flush()

    async def _periodic_flush(self) -> None:
        """Periodically flush the buffer."""
        while self._running:
            await asyncio.sleep(self.FLUSH_INTERVAL_SECONDS)
            await self.flush()

    async def start(self) -> None:
        """Start the audit logger background tasks."""
        self._running = True
        self._flush_task = asyncio.create_task(self._periodic_flush())

        # Clean up old logs on start
        await self._cleanup_old_logs()

        self.log(AuditEventType.DAEMON_START, details={"component": "audit_logger"})

    async def stop(self) -> None:
        """Stop the audit logger and flush remaining events."""
        self._running = False

        if self._flush_task:
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass

        self.log(AuditEventType.DAEMON_STOP, details={"component": "audit_logger"})
        await self.flush()

    async def _cleanup_old_logs(self) -> None:
        """Remove logs older than retention period."""
        cutoff = datetime.utcnow() - timedelta(days=self.retention_days)

        try:
            for log_file in self.log_dir.glob("audit-*.jsonl*"):
                # Extract date from filename
                try:
                    date_str = log_file.stem.replace("audit-", "").replace(".jsonl", "")
                    log_date = datetime.strptime(date_str, "%Y-%m-%d")

                    if log_date < cutoff:
                        log_file.unlink()
                        logger.info(f"Deleted old audit log: {log_file.name}")
                except (ValueError, OSError) as e:
                    logger.warning(f"Could not process log file {log_file}: {e}")

        except Exception as e:
            logger.error(f"Error during log cleanup: {e}")

    async def compress_old_logs(self) -> None:
        """Compress logs older than 1 day."""
        if not self.compress_old:
            return

        yesterday = datetime.utcnow() - timedelta(days=1)

        try:
            for log_file in self.log_dir.glob("audit-*.jsonl"):
                # Skip today's log
                date_str = log_file.stem.replace("audit-", "")
                log_date = datetime.strptime(date_str, "%Y-%m-%d")

                if log_date < yesterday:
                    gz_path = log_file.with_suffix(".jsonl.gz")

                    if not gz_path.exists():
                        with open(log_file, "rb") as f_in:
                            with gzip.open(gz_path, "wb") as f_out:
                                f_out.writelines(f_in)

                        log_file.unlink()
                        logger.info(f"Compressed audit log: {log_file.name}")

        except Exception as e:
            logger.error(f"Error compressing logs: {e}")

    def query(
        self,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        event_types: list[AuditEventType] | None = None,
        sender: str | None = None,
        limit: int = 1000,
    ) -> list[dict]:
        """
        Query audit logs with filters.

        Args:
            start_date: Start of date range
            end_date: End of date range
            event_types: Filter by event types
            sender: Filter by sender phone number
            limit: Maximum results to return

        Returns:
            List of matching audit events
        """
        if end_date is None:
            end_date = datetime.utcnow()
        if start_date is None:
            start_date = end_date - timedelta(days=7)

        results = []
        current = start_date

        while current <= end_date and len(results) < limit:
            log_file = self._get_log_file(current)
            gz_file = log_file.with_suffix(".jsonl.gz")

            # Try both compressed and uncompressed
            for path, opener in [(log_file, open), (gz_file, gzip.open)]:
                if path.exists():
                    try:
                        with opener(path, "rt") as f:
                            for line in f:
                                if len(results) >= limit:
                                    break

                                try:
                                    event = json.loads(line.strip())

                                    # Apply filters
                                    if event_types:
                                        if event.get("event_type") not in [
                                            e.value for e in event_types
                                        ]:
                                            continue

                                    if sender and event.get("sender") != sender:
                                        continue

                                    results.append(event)

                                except json.JSONDecodeError:
                                    continue
                    except Exception as e:
                        logger.error(f"Error reading {path}: {e}")

            current += timedelta(days=1)

        return results


# Singleton instance for global access
_audit_logger: AuditLogger | None = None


def get_audit_logger() -> AuditLogger:
    """Get the global audit logger instance."""
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger()
    return _audit_logger


def set_audit_logger(logger_instance: AuditLogger) -> None:
    """Set the global audit logger instance."""
    global _audit_logger
    _audit_logger = logger_instance
