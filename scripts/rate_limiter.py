#!/usr/bin/env python3
"""
Rate limiting implementation for JMP SMS security.

Uses sliding window algorithm for accurate rate limiting with
per-number and global limits to prevent abuse.
"""

import asyncio
import json
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import threading

logger = logging.getLogger(__name__)


class RateLimitType(str, Enum):
    """Types of rate limits."""
    MESSAGES_PER_MINUTE = "messages_per_minute"
    MESSAGES_PER_HOUR = "messages_per_hour"
    MESSAGES_PER_DAY = "messages_per_day"
    QUARANTINE_REQUESTS_PER_HOUR = "quarantine_requests_per_hour"
    UNKNOWN_NUMBERS_PER_HOUR = "unknown_numbers_per_hour"
    GLOBAL_MESSAGES_PER_HOUR = "global_messages_per_hour"
    SPOOF_CHALLENGES_PER_DAY = "spoof_challenges_per_day"


@dataclass
class RateLimitConfig:
    """Rate limit configuration."""
    # Per phone number limits
    messages_per_minute: int = 10
    messages_per_hour: int = 50
    messages_per_day: int = 200
    quarantine_requests_per_hour: int = 20
    spoof_challenges_per_day: int = 5
    
    # Global limits
    unknown_numbers_per_hour: int = 100
    global_messages_per_hour: int = 500
    global_quarantine_calls_per_hour: int = 200
    
    @classmethod
    def from_dict(cls, data: dict) -> 'RateLimitConfig':
        """Create config from dictionary."""
        return cls(**{k: v for k, v in data.items() if hasattr(cls, k)})
    
    @classmethod
    def load(cls, path: Path) -> 'RateLimitConfig':
        """Load config from JSON file."""
        if path.exists():
            with open(path) as f:
                return cls.from_dict(json.load(f))
        return cls()


@dataclass
class RateLimitResult:
    """Result of a rate limit check."""
    allowed: bool
    limit_type: Optional[RateLimitType] = None
    current_count: int = 0
    limit: int = 0
    retry_after_seconds: int = 0
    message: str = ""
    
    def to_dict(self) -> dict:
        return {
            'allowed': self.allowed,
            'limit_type': self.limit_type.value if self.limit_type else None,
            'current_count': self.current_count,
            'limit': self.limit,
            'retry_after_seconds': self.retry_after_seconds,
            'message': self.message
        }


class SlidingWindowCounter:
    """
    Sliding window rate limiter using a logarithmic approach.
    
    More accurate than fixed windows while being memory efficient.
    """
    
    def __init__(self, window_seconds: int, limit: int):
        self.window_seconds = window_seconds
        self.limit = limit
        self._prev_count = 0
        self._curr_count = 0
        self._window_start = 0
        self._lock = threading.Lock()
    
    def _get_window_info(self, now: float) -> Tuple[float, float]:
        """Get current window start and elapsed fraction."""
        window_start = (now // self.window_seconds) * self.window_seconds
        elapsed = (now - window_start) / self.window_seconds
        return window_start, elapsed
    
    def check(self, now: Optional[float] = None) -> Tuple[bool, int]:
        """
        Check if request is allowed.
        
        Returns:
            Tuple of (allowed, current_count)
        """
        if now is None:
            now = time.time()
            
        with self._lock:
            window_start, elapsed = self._get_window_info(now)
            
            # Handle window transitions
            if window_start > self._window_start:
                windows_passed = int((window_start - self._window_start) / self.window_seconds)
                
                if windows_passed == 1:
                    self._prev_count = self._curr_count
                    self._curr_count = 0
                else:
                    self._prev_count = 0
                    self._curr_count = 0
                    
                self._window_start = window_start
            
            # Calculate weighted count using sliding window approximation
            weighted_count = self._prev_count * (1 - elapsed) + self._curr_count
            
            return weighted_count < self.limit, int(weighted_count)
    
    def record(self, now: Optional[float] = None) -> None:
        """Record a request."""
        if now is None:
            now = time.time()
            
        with self._lock:
            window_start, _ = self._get_window_info(now)
            
            # Handle window transition
            if window_start > self._window_start:
                self._prev_count = self._curr_count
                self._curr_count = 1
                self._window_start = window_start
            else:
                self._curr_count += 1
    
    def check_and_record(self, now: Optional[float] = None) -> Tuple[bool, int]:
        """Check if allowed and record if so."""
        if now is None:
            now = time.time()
            
        allowed, count = self.check(now)
        if allowed:
            self.record(now)
            count += 1
        return allowed, count
    
    def time_until_allowed(self, now: Optional[float] = None) -> int:
        """Calculate seconds until a request would be allowed."""
        if now is None:
            now = time.time()
            
        allowed, _ = self.check(now)
        if allowed:
            return 0
        
        # Return time until window resets
        window_start, _ = self._get_window_info(now)
        next_window = window_start + self.window_seconds
        return max(1, int(next_window - now))


class RateLimiter:
    """
    Multi-tier rate limiter for SMS messages.
    
    Implements sliding window rate limiting at multiple time scales:
    - Per minute (burst protection)
    - Per hour (sustained rate)
    - Per day (daily quota)
    
    Also tracks global limits across all senders.
    """
    
    CONFIG_PATH = Path('/data/workspace/skills/jmp-sms/config/rate_limits.json')
    
    def __init__(self, config: Optional[RateLimitConfig] = None):
        self.config = config or RateLimitConfig.load(self.CONFIG_PATH)
        
        # Per-number counters: phone -> {limit_type -> counter}
        self._number_counters: Dict[str, Dict[str, SlidingWindowCounter]] = defaultdict(dict)
        
        # Global counters
        self._global_counters: Dict[str, SlidingWindowCounter] = {}
        
        # Track unique unknown numbers per hour
        self._unknown_numbers_hourly: Dict[int, set] = defaultdict(set)
        
        self._lock = threading.Lock()
        
        # Initialize global counters
        self._init_global_counters()
    
    def _init_global_counters(self) -> None:
        """Initialize global rate limit counters."""
        self._global_counters = {
            'messages_hour': SlidingWindowCounter(3600, self.config.global_messages_per_hour),
            'quarantine_hour': SlidingWindowCounter(3600, self.config.global_quarantine_calls_per_hour),
        }
    
    def _get_number_counters(self, phone: str) -> Dict[str, SlidingWindowCounter]:
        """Get or create counters for a phone number."""
        with self._lock:
            if phone not in self._number_counters:
                self._number_counters[phone] = {
                    'minute': SlidingWindowCounter(60, self.config.messages_per_minute),
                    'hour': SlidingWindowCounter(3600, self.config.messages_per_hour),
                    'day': SlidingWindowCounter(86400, self.config.messages_per_day),
                    'quarantine': SlidingWindowCounter(3600, self.config.quarantine_requests_per_hour),
                    'spoof_challenge': SlidingWindowCounter(86400, self.config.spoof_challenges_per_day),
                }
            return self._number_counters[phone]
    
    def _cleanup_old_windows(self) -> None:
        """Remove counters for numbers we haven't seen recently."""
        # This prevents unbounded memory growth
        # In practice, we'd run this periodically
        pass
    
    def check_message(self, phone: str, is_unknown: bool = False) -> RateLimitResult:
        """
        Check if an incoming message is allowed.
        
        Args:
            phone: Sender phone number
            is_unknown: Whether this is an unknown number
            
        Returns:
            RateLimitResult indicating if message is allowed
        """
        now = time.time()
        counters = self._get_number_counters(phone)
        
        # Check per-number limits (minute -> hour -> day)
        checks = [
            ('minute', RateLimitType.MESSAGES_PER_MINUTE, self.config.messages_per_minute),
            ('hour', RateLimitType.MESSAGES_PER_HOUR, self.config.messages_per_hour),
            ('day', RateLimitType.MESSAGES_PER_DAY, self.config.messages_per_day),
        ]
        
        for key, limit_type, limit in checks:
            counter = counters[key]
            allowed, count = counter.check(now)
            
            if not allowed:
                return RateLimitResult(
                    allowed=False,
                    limit_type=limit_type,
                    current_count=count,
                    limit=limit,
                    retry_after_seconds=counter.time_until_allowed(now),
                    message=f"Rate limit exceeded: {limit_type.value}"
                )
        
        # Check global message limit
        global_counter = self._global_counters['messages_hour']
        allowed, count = global_counter.check(now)
        if not allowed:
            return RateLimitResult(
                allowed=False,
                limit_type=RateLimitType.GLOBAL_MESSAGES_PER_HOUR,
                current_count=count,
                limit=self.config.global_messages_per_hour,
                retry_after_seconds=global_counter.time_until_allowed(now),
                message="Global rate limit exceeded"
            )
        
        # Check unknown numbers limit
        if is_unknown:
            hour_bucket = int(now // 3600)
            with self._lock:
                # Clean up old buckets
                old_buckets = [b for b in self._unknown_numbers_hourly if b < hour_bucket - 1]
                for b in old_buckets:
                    del self._unknown_numbers_hourly[b]
                
                unknown_count = len(self._unknown_numbers_hourly[hour_bucket])
                
                if unknown_count >= self.config.unknown_numbers_per_hour:
                    return RateLimitResult(
                        allowed=False,
                        limit_type=RateLimitType.UNKNOWN_NUMBERS_PER_HOUR,
                        current_count=unknown_count,
                        limit=self.config.unknown_numbers_per_hour,
                        retry_after_seconds=int((hour_bucket + 1) * 3600 - now),
                        message="Too many unknown numbers this hour"
                    )
        
        return RateLimitResult(allowed=True, message="OK")
    
    def record_message(self, phone: str, is_unknown: bool = False) -> None:
        """Record that a message was processed."""
        now = time.time()
        counters = self._get_number_counters(phone)
        
        # Record in all per-number counters
        counters['minute'].record(now)
        counters['hour'].record(now)
        counters['day'].record(now)
        
        # Record in global counter
        self._global_counters['messages_hour'].record(now)
        
        # Track unknown number
        if is_unknown:
            hour_bucket = int(now // 3600)
            with self._lock:
                self._unknown_numbers_hourly[hour_bucket].add(phone)
    
    def check_quarantine_request(self, phone: str) -> RateLimitResult:
        """Check if a quarantine request is allowed."""
        now = time.time()
        counters = self._get_number_counters(phone)
        
        # Check per-number quarantine limit
        counter = counters['quarantine']
        allowed, count = counter.check(now)
        
        if not allowed:
            return RateLimitResult(
                allowed=False,
                limit_type=RateLimitType.QUARANTINE_REQUESTS_PER_HOUR,
                current_count=count,
                limit=self.config.quarantine_requests_per_hour,
                retry_after_seconds=counter.time_until_allowed(now),
                message="Quarantine request limit exceeded"
            )
        
        # Check global quarantine limit
        global_counter = self._global_counters['quarantine_hour']
        allowed, count = global_counter.check(now)
        
        if not allowed:
            return RateLimitResult(
                allowed=False,
                limit_type=RateLimitType.GLOBAL_MESSAGES_PER_HOUR,
                current_count=count,
                limit=self.config.global_quarantine_calls_per_hour,
                retry_after_seconds=global_counter.time_until_allowed(now),
                message="Global quarantine limit exceeded"
            )
        
        return RateLimitResult(allowed=True, message="OK")
    
    def record_quarantine_request(self, phone: str) -> None:
        """Record that a quarantine request was made."""
        now = time.time()
        counters = self._get_number_counters(phone)
        
        counters['quarantine'].record(now)
        self._global_counters['quarantine_hour'].record(now)
    
    def check_spoof_challenge(self, phone: str) -> RateLimitResult:
        """Check if we can send a spoof challenge."""
        now = time.time()
        counters = self._get_number_counters(phone)
        counter = counters['spoof_challenge']
        
        allowed, count = counter.check(now)
        
        if not allowed:
            return RateLimitResult(
                allowed=False,
                limit_type=RateLimitType.SPOOF_CHALLENGES_PER_DAY,
                current_count=count,
                limit=self.config.spoof_challenges_per_day,
                retry_after_seconds=counter.time_until_allowed(now),
                message="Too many spoof challenges today"
            )
        
        return RateLimitResult(allowed=True, message="OK")
    
    def record_spoof_challenge(self, phone: str) -> None:
        """Record that a spoof challenge was sent."""
        now = time.time()
        counters = self._get_number_counters(phone)
        counters['spoof_challenge'].record(now)
    
    def get_status(self, phone: str) -> dict:
        """Get current rate limit status for a phone number."""
        now = time.time()
        counters = self._get_number_counters(phone)
        
        status = {}
        for key, counter in counters.items():
            allowed, count = counter.check(now)
            status[key] = {
                'count': count,
                'limit': counter.limit,
                'allowed': allowed,
                'retry_after': counter.time_until_allowed(now) if not allowed else 0
            }
        
        return status
    
    def reset_number(self, phone: str) -> None:
        """Reset all rate limits for a phone number."""
        with self._lock:
            if phone in self._number_counters:
                del self._number_counters[phone]
    
    def get_stats(self) -> dict:
        """Get overall rate limiter statistics."""
        now = time.time()
        hour_bucket = int(now // 3600)
        
        with self._lock:
            return {
                'tracked_numbers': len(self._number_counters),
                'unknown_this_hour': len(self._unknown_numbers_hourly.get(hour_bucket, set())),
                'global_messages_hour': {
                    'count': self._global_counters['messages_hour'].check(now)[1],
                    'limit': self.config.global_messages_per_hour
                },
                'global_quarantine_hour': {
                    'count': self._global_counters['quarantine_hour'].check(now)[1],
                    'limit': self.config.global_quarantine_calls_per_hour
                }
            }


# Singleton instance
_rate_limiter: Optional[RateLimiter] = None


def get_rate_limiter() -> RateLimiter:
    """Get the global rate limiter instance."""
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = RateLimiter()
    return _rate_limiter


def set_rate_limiter(limiter: RateLimiter) -> None:
    """Set the global rate limiter instance."""
    global _rate_limiter
    _rate_limiter = limiter
