#!/usr/bin/env python3
"""
SMS listener/receiver for JMP.chat.

Runs as a persistent process to receive incoming SMS messages.
Messages are logged to message_history.jsonl and can optionally
trigger webhooks or callbacks.

Usage:
    python receive_sms.py              # Run listener
    python receive_sms.py --once       # Receive one message then exit
    python receive_sms.py --timeout 60 # Run for 60 seconds
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

from jmp_client import JMPClient, load_credentials, CREDENTIALS_PATH

logger = logging.getLogger(__name__)


class SMSReceiver:
    """SMS receiver that listens for incoming messages."""
    
    def __init__(
        self,
        credentials_path: Path = CREDENTIALS_PATH,
        callback=None,
        once: bool = False
    ):
        self.credentials_path = credentials_path
        self.user_callback = callback
        self.once = once
        self.client = None
        self.received_count = 0
        self.stop_event = asyncio.Event()
        
    def on_message(self, phone: str, body: str, timestamp: str):
        """Handle received SMS."""
        self.received_count += 1
        
        print(f"\n{'='*50}")
        print(f"📱 SMS RECEIVED")
        print(f"From: {phone}")
        print(f"Time: {timestamp}")
        print(f"Message: {body}")
        print(f"{'='*50}\n")
        
        # Call user callback if provided
        if self.user_callback:
            try:
                self.user_callback(phone, body, timestamp)
            except Exception as e:
                logger.error(f"Callback error: {e}")
                
        # If --once mode, signal to stop
        if self.once:
            self.stop_event.set()
            
    async def run(self, timeout: float = None):
        """
        Run the SMS receiver.
        
        Args:
            timeout: Optional timeout in seconds (None = run forever)
        """
        creds = load_credentials(self.credentials_path)
        
        self.client = JMPClient(
            creds['jabber_id'],
            creds['password'],
            creds.get('sms_gateway', 'cheogram.com'),
            message_callback=self.on_message
        )
        
        print(f"Connecting to {creds['xmpp_server']}...")
        self.client.connect()
        
        if not await self.client.wait_connected():
            print("Failed to connect!")
            return False
            
        print(f"✓ Connected as {self.client.boundjid.bare}")
        print(f"📱 Phone: {creds['phone_number']}")
        print("Listening for incoming SMS... (Ctrl+C to stop)\n")
        
        # Wait for stop signal or timeout
        try:
            if timeout:
                await asyncio.wait_for(
                    self.stop_event.wait(),
                    timeout=timeout
                )
            else:
                await self.stop_event.wait()
        except asyncio.TimeoutError:
            print(f"\nTimeout reached ({timeout}s)")
        except asyncio.CancelledError:
            print("\nReceiver cancelled")
            
        print(f"\nReceived {self.received_count} messages total")
        self.client.disconnect()
        return True
        
    def stop(self):
        """Stop the receiver."""
        self.stop_event.set()


async def main_async(args):
    """Async main function."""
    receiver = SMSReceiver(
        credentials_path=args.credentials,
        once=args.once
    )
    
    # Handle Ctrl+C
    def signal_handler():
        print("\nShutting down...")
        receiver.stop()
        
    loop = asyncio.get_event_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, signal_handler)
        except NotImplementedError:
            # Windows doesn't support add_signal_handler
            pass
    
    timeout = args.timeout if args.timeout > 0 else None
    await receiver.run(timeout=timeout)


def main():
    parser = argparse.ArgumentParser(description='Receive SMS via JMP.chat')
    parser.add_argument(
        '--credentials', '-c',
        type=Path,
        default=CREDENTIALS_PATH,
        help='Path to credentials JSON file'
    )
    parser.add_argument(
        '--once',
        action='store_true',
        help='Exit after receiving one message'
    )
    parser.add_argument(
        '--timeout', '-t',
        type=float,
        default=0,
        help='Timeout in seconds (0 = run forever)'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose logging'
    )
    
    args = parser.parse_args()
    
    # Setup logging
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        print("\nBye!")


if __name__ == '__main__':
    main()
