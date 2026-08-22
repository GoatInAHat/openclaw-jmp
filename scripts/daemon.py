#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["slixmpp>=1.8,<2", "pydantic>=2,<3", "requests>=2.28,<3"]
# ///
"""
JMP SMS Security Daemon

Main entry point that:
- Starts XMPP listener
- Initializes all security components
- Handles graceful shutdown
- Manages concurrent message processing

Usage:
    python daemon.py              # Run daemon
    python daemon.py --test       # Run with test mode (limited timeout)
    python daemon.py --config /path/to/config.json
"""

import argparse
import asyncio
import json
import logging
import signal
import sys
from datetime import datetime
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

# Local security modules
from audit_logger import AuditEventType, AuditLogger, set_audit_logger
from jmp_client import CREDENTIALS_PATH, JMPClient, load_credentials
from main_agent_interface import MainAgentInterface
from message_coordinator import MessageCoordinator
from paths import CONFIG_DIR, DATA_DIR
from rate_limiter import RateLimitConfig, RateLimiter, set_rate_limiter

# Optional modules (may be created by other subagents)
try:
    from routing_engine import RoutingEngine
except ImportError:
    RoutingEngine = None

try:
    from anti_spoof import AntiSpoofChecker
except ImportError:
    AntiSpoofChecker = None

try:
    from quarantine_handler import QuarantineHandler
except ImportError:
    QuarantineHandler = None

try:
    from owner_verification import OwnerVerificationManager
except ImportError:
    OwnerVerificationManager = None


logger = logging.getLogger(__name__)


class SMSDaemon:
    """
    Main daemon process for JMP SMS security system.

    Manages the lifecycle of all components and handles
    incoming messages through the security pipeline.
    """

    CONFIG_PATH = CONFIG_DIR / "daemon.json"

    def __init__(
        self,
        credentials_path: Path = CREDENTIALS_PATH,
        config_path: Path | None = None,
        test_mode: bool = False,
    ):
        self.credentials_path = credentials_path
        self.config_path = config_path or self.CONFIG_PATH
        self.test_mode = test_mode

        # Components (initialized in start())
        self.jmp_client: JMPClient | None = None
        self.coordinator: MessageCoordinator | None = None
        self.audit_logger: AuditLogger | None = None
        self.rate_limiter: RateLimiter | None = None

        # State
        self._running = False
        self._shutdown_event = asyncio.Event()
        self._message_queue: asyncio.Queue = asyncio.Queue()
        self._workers: list = []

        # Configuration
        self.config = self._load_config()

        # Stats
        self._start_time: datetime | None = None
        self._messages_processed = 0
        self._errors = 0

    def _load_config(self) -> dict:
        """Load daemon configuration."""
        defaults = {
            "worker_count": 4,
            "max_queue_size": 100,
            "cleanup_interval_seconds": 300,
            "stats_interval_seconds": 60,
            "notify_channel": "discord",
            "log_level": "INFO",
        }

        if self.config_path.exists():
            try:
                with open(self.config_path) as f:
                    loaded = json.load(f)
                    defaults.update(loaded)
            except Exception as e:
                logger.warning(f"Could not load config: {e}")

        return defaults

    async def start(self) -> None:
        """Start the daemon and all components."""
        logger.info("Starting JMP SMS Security Daemon...")
        self._running = True
        self._start_time = datetime.utcnow()

        try:
            # Initialize audit logger
            self.audit_logger = AuditLogger()
            set_audit_logger(self.audit_logger)
            await self.audit_logger.start()

            # Initialize rate limiter
            rate_config = RateLimitConfig.load(CONFIG_DIR / "rate_limits.json")
            self.rate_limiter = RateLimiter(rate_config)
            set_rate_limiter(self.rate_limiter)

            # Initialize optional components
            routing_engine = RoutingEngine() if RoutingEngine else None
            anti_spoof = AntiSpoofChecker() if AntiSpoofChecker else None
            quarantine = QuarantineHandler() if QuarantineHandler else None

            # Initialize main agent interface
            main_interface = MainAgentInterface(
                send_to_main=self._send_to_main_agent, escalation_callback=self._handle_escalation
            )

            # Initialize coordinator
            self.coordinator = MessageCoordinator(
                routing_engine=routing_engine,
                anti_spoof_checker=anti_spoof,
                quarantine_handler=quarantine,
                rate_limiter=self.rate_limiter,
                audit_logger=self.audit_logger,
                main_interface=main_interface,
                send_sms_callback=self._send_sms,
                notify_owner_callback=self._notify_owner,
            )

            # Initialize JMP client
            creds = load_credentials(self.credentials_path)
            self.jmp_client = JMPClient(
                creds["jabber_id"],
                creds["password"],
                creds.get("sms_gateway", "cheogram.com"),
                message_callback=self._on_message_received,
                log_messages=True,
            )

            # Log daemon start
            self.audit_logger.log(
                AuditEventType.DAEMON_START,
                details={
                    "version": "1.0.0",
                    "test_mode": self.test_mode,
                    "worker_count": self.config["worker_count"],
                },
            )

            # Connect to XMPP
            logger.info(f"Connecting to XMPP as {creds['jabber_id']}...")
            self.jmp_client.connect()

            if not await self.jmp_client.wait_connected():
                raise RuntimeError("Failed to connect to XMPP server")

            logger.info(f"✓ Connected as {self.jmp_client.boundjid.bare}")
            logger.info(f"📱 Phone: {creds['phone_number']}")

            # Start worker tasks
            for i in range(self.config["worker_count"]):
                worker = asyncio.create_task(self._message_worker(i))
                self._workers.append(worker)

            # Start maintenance tasks
            cleanup_task = asyncio.create_task(self._cleanup_loop())
            self._workers.append(cleanup_task)

            if not self.test_mode:
                stats_task = asyncio.create_task(self._stats_loop())
                self._workers.append(stats_task)

            logger.info(f"✓ Daemon started with {self.config['worker_count']} workers")
            logger.info("Listening for incoming SMS... (Ctrl+C to stop)\n")

            # Wait for shutdown signal
            await self._shutdown_event.wait()

        except Exception as e:
            logger.exception(f"Daemon startup failed: {e}")
            raise
        finally:
            await self.stop()

    async def stop(self) -> None:
        """Stop the daemon and all components."""
        if not self._running:
            return

        logger.info("Shutting down daemon...")
        self._running = False
        self._shutdown_event.set()

        # Cancel all workers
        for worker in self._workers:
            worker.cancel()

        if self._workers:
            await asyncio.gather(*self._workers, return_exceptions=True)

        # Disconnect XMPP
        if self.jmp_client:
            self.jmp_client.disconnect()

        # Log daemon stop
        if self.audit_logger:
            self.audit_logger.log(
                AuditEventType.DAEMON_STOP,
                details={
                    "uptime_seconds": (datetime.utcnow() - self._start_time).total_seconds()
                    if self._start_time
                    else 0,
                    "messages_processed": self._messages_processed,
                    "errors": self._errors,
                },
            )
            await self.audit_logger.stop()

        logger.info("Daemon stopped.")

    def _on_message_received(self, phone: str, body: str, timestamp: str) -> None:
        """Callback for received SMS messages (called from XMPP thread)."""
        # Put message in queue for async processing
        try:
            # Create InboundSMS
            from api_schema import InboundSMS
        except ImportError:
            # Use simple dict if schema not available
            class InboundSMS:
                def __init__(self, **kwargs):
                    for k, v in kwargs.items():
                        setattr(self, k, v)

        sms = InboundSMS(
            sender=phone,
            recipient="+15550001234",  # Your JMP number
            body=body,
            timestamp=timestamp,
            message_id=str(hash(f"{phone}{timestamp}{body}")),
            media=[],
            carrier_info=None,
            voice_attestation=None,
        )

        # Queue for processing
        try:
            self._message_queue.put_nowait(sms)
        except asyncio.QueueFull:
            logger.error(f"Message queue full, dropping message from {phone}")
            self._errors += 1

    async def _message_worker(self, worker_id: int) -> None:
        """Worker coroutine that processes messages from the queue."""
        logger.debug(f"Worker {worker_id} started")

        while self._running:
            try:
                # Wait for message with timeout
                try:
                    sms = await asyncio.wait_for(self._message_queue.get(), timeout=1.0)
                except asyncio.TimeoutError:
                    continue

                # Process message
                logger.debug(f"Worker {worker_id} processing message from {sms.sender}")

                try:
                    response = await self.coordinator.process_message(sms)
                    self._messages_processed += 1

                    if response:
                        logger.info(f"Processed message from {sms.sender}, response sent")
                    else:
                        logger.info(f"Processed message from {sms.sender}, no response")

                except Exception as e:
                    logger.exception(f"Error processing message: {e}")
                    self._errors += 1

                self._message_queue.task_done()

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.exception(f"Worker {worker_id} error: {e}")
                self._errors += 1

        logger.debug(f"Worker {worker_id} stopped")

    async def _cleanup_loop(self) -> None:
        """Periodic cleanup of expired conversations and challenges."""
        interval = self.config["cleanup_interval_seconds"]

        while self._running:
            try:
                await asyncio.sleep(interval)

                if self.coordinator:
                    await self.coordinator.cleanup()

                if self.audit_logger:
                    await self.audit_logger.compress_old_logs()

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Cleanup error: {e}")

    async def _stats_loop(self) -> None:
        """Periodic stats logging."""
        interval = self.config["stats_interval_seconds"]

        while self._running:
            try:
                await asyncio.sleep(interval)

                stats = {
                    "messages_processed": self._messages_processed,
                    "errors": self._errors,
                    "queue_size": self._message_queue.qsize(),
                    "uptime_seconds": (datetime.utcnow() - self._start_time).total_seconds()
                    if self._start_time
                    else 0,
                }

                if self.coordinator:
                    stats.update(self.coordinator.get_stats())

                logger.info(f"Stats: {json.dumps(stats)}")

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Stats error: {e}")

    async def _send_sms(self, recipient: str, message: str) -> None:
        """Send an SMS via JMP client."""
        if self.jmp_client:
            self.jmp_client.send_sms(recipient, message)

    async def _send_to_main_agent(self, message: str, channel: str = "sms", **kwargs) -> str | None:
        """
        Send a message to the main OpenClaw agent.

        This is a placeholder - in production, this would integrate
        with OpenClaw's session system to send messages to the main agent.
        """
        # TODO: Integrate with OpenClaw session/message system
        # For now, log and return a placeholder response
        logger.info(f"Would send to main agent ({channel}): {message[:100]}...")

        # In production, this would:
        # 1. Send message to main agent session
        # 2. Wait for response
        # 3. Return the response text

        # Placeholder response
        return None

    async def _handle_escalation(self, escalation_data: dict) -> None:
        """Handle an escalation notification."""
        logger.info(f"Escalation: {escalation_data}")

        # TODO: Send to owner via Discord or other trusted channel
        # For now, just log it
        if self.audit_logger:
            self.audit_logger.log(AuditEventType.ESCALATION, details=escalation_data)

    async def _notify_owner(self, message: str, urgent: bool = False) -> None:
        """Send a notification to the owner."""
        channel = self.config.get("notify_channel", "discord")

        # TODO: Integrate with OpenClaw notification system
        logger.info(f"Owner notification ({channel}, urgent={urgent}): {message[:100]}...")

        if self.audit_logger:
            self.audit_logger.log(
                AuditEventType.SECURITY_ALERT,
                details={"notification": message[:200], "urgent": urgent, "channel": channel},
            )


async def run_daemon(args: argparse.Namespace) -> None:
    """Run the daemon with signal handling."""
    daemon = SMSDaemon(
        credentials_path=args.credentials, config_path=args.config, test_mode=args.test
    )

    # Set up signal handlers
    loop = asyncio.get_event_loop()

    def signal_handler():
        logger.info("Received shutdown signal")
        daemon._shutdown_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, signal_handler)
        except NotImplementedError:
            # Windows doesn't support add_signal_handler
            pass

    # Run daemon
    if args.test:
        # In test mode, run for limited time
        try:
            await asyncio.wait_for(daemon.start(), timeout=args.timeout or 30)
        except asyncio.TimeoutError:
            logger.info("Test timeout reached")
    else:
        await daemon.start()


def main():
    parser = argparse.ArgumentParser(
        description="JMP SMS Security Daemon",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python daemon.py                    # Run daemon normally
    python daemon.py --test             # Run in test mode (30s timeout)
    python daemon.py --test --timeout 60  # Test mode with 60s timeout
    python daemon.py -v                 # Verbose logging
        """,
    )
    parser.add_argument(
        "--credentials",
        "-c",
        type=Path,
        default=CREDENTIALS_PATH,
        help="Path to JMP credentials JSON file",
    )
    parser.add_argument(
        "--config", type=Path, default=None, help="Path to daemon configuration JSON file"
    )
    parser.add_argument("--test", action="store_true", help="Run in test mode with timeout")
    parser.add_argument(
        "--timeout", "-t", type=float, default=30, help="Timeout in seconds for test mode"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose (DEBUG) logging"
    )

    args = parser.parse_args()

    # Set up logging
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler(), logging.FileHandler(DATA_DIR / "daemon.log")],
    )

    # Reduce noise from slixmpp
    logging.getLogger("slixmpp").setLevel(logging.WARNING)

    # Ensure data directory exists
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    try:
        asyncio.run(run_daemon(args))
    except KeyboardInterrupt:
        print("\nBye!")


if __name__ == "__main__":
    main()
