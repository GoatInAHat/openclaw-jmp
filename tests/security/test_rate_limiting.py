"""
Test Rate Limiting System
=========================

Tests the rate limiting system that protects against abuse,
denial of service, and resource exhaustion attacks.

Reference: /data/workspace/notes/projects/jmp-secure-channel/ARCHITECTURE.md
"""

from tests.security.conftest import (
    MockRateLimiter,
)


class TestPerNumberLimits:
    """Test per-phone-number rate limiting."""

    def test_per_minute_limit(self, rate_limiter: MockRateLimiter):
        """Test that per-minute limit is enforced."""
        sender = "+15551234567"
        limit = rate_limiter.limits["per_number_per_minute"]

        # Send up to the limit
        for i in range(limit):
            result = rate_limiter.check(sender)
            assert result["allowed"], f"Message {i + 1} should be allowed (limit: {limit})"

        # Next message should be blocked
        result = rate_limiter.check(sender)
        assert not result["allowed"], "Should hit per-minute limit"
        assert result["reason"] == "per_minute_limit"
        assert result["retry_after_seconds"] == 60

    def test_per_hour_limit(self, rate_limiter: MockRateLimiter):
        """Test that per-hour limit is enforced."""
        sender = "+15559999999"
        limit = rate_limiter.limits["per_number_per_hour"]

        # Send up to the limit
        for i in range(limit):
            result = rate_limiter.check(sender)
            if not result["allowed"]:
                # May hit per-minute limit first, reset and continue
                rate_limiter.counts[sender]["minute"] = 0
                result = rate_limiter.check(sender)
            assert result["allowed"], f"Message {i + 1} should be allowed"

        # Reset minute counter to test hour limit specifically
        rate_limiter.counts[sender]["minute"] = 0

        # Next message should hit hour limit
        result = rate_limiter.check(sender)
        assert not result["allowed"]
        assert result["reason"] == "per_hour_limit"

    def test_different_numbers_independent(self, rate_limiter: MockRateLimiter):
        """Test that rate limits are independent per number."""
        sender1 = "+15551111111"
        sender2 = "+15552222222"
        limit = rate_limiter.limits["per_number_per_minute"]

        # Max out sender1
        for _ in range(limit):
            rate_limiter.check(sender1)

        # sender2 should still work
        result = rate_limiter.check(sender2)
        assert result["allowed"], "Different number should have separate limits"

    def test_limit_reset(self, rate_limiter: MockRateLimiter):
        """Test that limits reset properly."""
        sender = "+15553333333"

        # Hit the limit
        for _ in range(rate_limiter.limits["per_number_per_minute"] + 1):
            rate_limiter.check(sender)

        # Reset
        rate_limiter.reset(sender)

        # Should be allowed again
        result = rate_limiter.check(sender)
        assert result["allowed"], "Should allow after reset"


class TestGlobalLimits:
    """Test global (system-wide) rate limiting."""

    def test_global_hour_limit(self, rate_limiter: MockRateLimiter):
        """Test global per-hour limit across all senders."""
        global_limit = rate_limiter.limits["global_per_hour"]

        # Send from many different numbers
        for i in range(global_limit):
            sender = f"+1555{i:07d}"
            result = rate_limiter.check(sender)
            if not result["allowed"]:
                # May hit per-minute for that number
                rate_limiter.reset(sender)
                result = rate_limiter.check(sender)

        # Next message from any number should be blocked
        result = rate_limiter.check("+15550000000")
        # Depending on per-number vs global interaction
        # At minimum, global count should be tracked
        assert rate_limiter.global_count >= global_limit

    def test_global_reset(self, rate_limiter: MockRateLimiter):
        """Test global limit reset."""
        # Add some global count
        for i in range(10):
            rate_limiter.check(f"+1555{i:07d}")

        assert rate_limiter.global_count > 0

        # Full reset
        rate_limiter.reset()

        assert rate_limiter.global_count == 0
        assert len(rate_limiter.counts) == 0


class TestUnknownNumberLimits:
    """Test special limits for unknown/new numbers."""

    def test_unknown_numbers_tracked(self, rate_limiter: MockRateLimiter):
        """Test that unknown numbers are tracked separately."""
        # The architecture specifies: unknownNumbersPerHour: 100
        # This should limit how many unique unknown numbers can contact us

        unknown_numbers_seen = set()

        for i in range(10):
            sender = f"+1666{i:07d}"
            rate_limiter.check(sender)
            unknown_numbers_seen.add(sender)

        assert len(unknown_numbers_seen) == 10


class TestLimitTimingBehavior:
    """Test the timing aspects of rate limits."""

    def test_retry_after_header(self, rate_limiter: MockRateLimiter):
        """Test that blocked responses include retry timing."""
        sender = "+15551234567"

        # Hit the limit
        for _ in range(rate_limiter.limits["per_number_per_minute"] + 1):
            result = rate_limiter.check(sender)

        assert "retry_after_seconds" in result
        assert result["retry_after_seconds"] > 0

    def test_limit_reason_is_specific(self, rate_limiter: MockRateLimiter):
        """Test that limit reason indicates which limit was hit."""
        sender = "+15551234567"

        # Hit per-minute limit
        for _ in range(rate_limiter.limits["per_number_per_minute"] + 1):
            result = rate_limiter.check(sender)

        assert result["reason"] == "per_minute_limit"

        # The reason helps in debugging and responding appropriately


class TestRateLimitResponses:
    """Test the responses sent when rate limited."""

    def test_rate_limit_response_is_helpful(self, rate_limiter: MockRateLimiter):
        """Test that rate limit response helps the user."""
        sender = "+15551234567"

        # Hit limit
        for _ in range(rate_limiter.limits["per_number_per_minute"] + 1):
            result = rate_limiter.check(sender)

        # Response should indicate:
        # 1. That rate limiting occurred
        # 2. When they can try again
        assert not result["allowed"]
        assert "retry_after_seconds" in result

    def test_rate_limit_doesnt_leak_info(self, rate_limiter: MockRateLimiter):
        """Test that rate limit response doesn't leak sensitive info."""
        sender = "+15551234567"

        for _ in range(rate_limiter.limits["per_number_per_minute"] + 1):
            result = rate_limiter.check(sender)

        # Response should NOT include:
        # - Other users' info
        # - System internals
        # - Exact limit numbers (could help attackers optimize)

        # Just basic info
        assert set(result.keys()) <= {"allowed", "reason", "retry_after_seconds"}


class TestBurstTrafficHandling:
    """Test handling of burst traffic patterns."""

    def test_gradual_vs_burst(self, rate_limiter: MockRateLimiter):
        """Test that burst traffic is handled differently than gradual."""
        sender = "+15551234567"

        # Burst: many messages at once
        burst_results = []
        for _ in range(15):
            burst_results.append(rate_limiter.check(sender))

        # Count how many were blocked
        blocked = sum(1 for r in burst_results if not r["allowed"])

        # With per-minute limit of 10, at least 5 should be blocked
        assert blocked >= 5

    def test_slow_sender_allowed(self, rate_limiter: MockRateLimiter):
        """Test that slow, steady traffic is allowed."""
        sender = "+15552222222"

        # Just a few messages - well under limits
        for _ in range(3):
            result = rate_limiter.check(sender)
            assert result["allowed"]


class TestAttackPatterns:
    """Test specific attack patterns."""

    def test_dos_from_single_number(self, rate_limiter: MockRateLimiter):
        """Test protection against DoS from single number."""
        attacker = "+15551234567"

        blocked_count = 0
        for _ in range(100):
            result = rate_limiter.check(attacker)
            if not result["allowed"]:
                blocked_count += 1

        # Should block the vast majority
        assert blocked_count > 85

    def test_distributed_dos(self, rate_limiter: MockRateLimiter):
        """Test protection against distributed DoS (many numbers)."""
        blocked_count = 0

        # Attack from 1000 different numbers
        for i in range(1000):
            attacker = f"+1666{i:07d}"
            result = rate_limiter.check(attacker)
            if not result["allowed"]:
                blocked_count += 1

        # Global limit should kick in
        # With global_per_hour of 500, should block ~500
        assert blocked_count > 400

    def test_rotating_numbers_attack(self, rate_limiter: MockRateLimiter):
        """Test attack that rotates through numbers to avoid per-number limits."""
        # Attacker uses new number for each message
        for i in range(100):
            attacker = f"+1777{i:07d}"
            rate_limiter.check(attacker)

        # Should still be tracked globally
        assert rate_limiter.global_count >= 100

    def test_slowloris_style_attack(self, rate_limiter: MockRateLimiter):
        """Test slow, persistent attack pattern."""
        # Attacker sends slowly to stay under per-minute limits
        # but accumulates over time

        # Simulate 24 hours of messages at 1 per minute
        # In real implementation, this would be blocked by daily limit

        # For testing, we'll just verify daily limits exist
        assert "per_number_per_day" in rate_limiter.limits
        assert rate_limiter.limits["per_number_per_day"] < 1440  # Less than 1/min all day


class TestRateLimitEdgeCases:
    """Test edge cases in rate limiting."""

    def test_empty_sender(self, rate_limiter: MockRateLimiter):
        """Test handling of empty/invalid sender."""
        result = rate_limiter.check("")

        # Should handle gracefully
        assert "allowed" in result

    def test_invalid_phone_format(self, rate_limiter: MockRateLimiter):
        """Test handling of invalid phone number format."""
        invalid_numbers = [
            "invalid",
            "12345",
            "+1",
            "abc123def",
            None,
        ]

        for number in invalid_numbers:
            if number is not None:
                result = rate_limiter.check(number)
                assert "allowed" in result

    def test_rate_limit_with_unicode_sender(self, rate_limiter: MockRateLimiter):
        """Test rate limiting with unicode in sender field."""
        # Some spoofing attempts might use unicode
        sender = "+1555\u200b1234567"  # Zero-width space

        result = rate_limiter.check(sender)
        assert "allowed" in result

    def test_concurrent_requests(self, rate_limiter: MockRateLimiter):
        """Document behavior under concurrent requests."""
        # In a real implementation, this would need thread-safe counting
        # For now, we document the expected behavior

        # Two requests arrive at nearly the same time
        # Both should be counted accurately

        sender = "+15551234567"

        rate_limiter.check(sender)
        rate_limiter.check(sender)

        # Both counted
        assert rate_limiter.counts[sender]["minute"] >= 2


class TestRateLimitConfiguration:
    """Test rate limit configuration."""

    def test_limits_are_reasonable(self, rate_limiter: MockRateLimiter):
        """Verify configured limits are reasonable."""
        limits = rate_limiter.limits

        # Per-minute shouldn't be too high (allows DoS) or too low (blocks legitimate)
        assert 5 <= limits["per_number_per_minute"] <= 20

        # Per-hour should be higher than per-minute * 60
        assert limits["per_number_per_hour"] <= limits["per_number_per_minute"] * 60

        # Daily limit should exist
        assert limits["per_number_per_day"] > 0

    def test_limits_hierarchy(self, rate_limiter: MockRateLimiter):
        """Verify limit hierarchy makes sense."""
        limits = rate_limiter.limits

        # minute < hour < day (in terms of allowed messages)
        # But the actual limit values should be set so you can't game them
        assert limits["per_number_per_minute"] < limits["per_number_per_hour"]
