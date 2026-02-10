#!/usr/bin/env python3
"""
Anti-Spoof Detection System for JMP Secure SMS Channel.

Analyzes incoming messages for signs of caller ID spoofing:
- Carrier consistency (has carrier changed unexpectedly?)
- Timing patterns (unusual hours, rapid-fire messages?)
- Behavioral patterns (does message style match history?)
- Voice attestation (STIR/SHAKEN for voice calls)
"""

from __future__ import annotations

import json
import logging
import re
import statistics
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from routing_engine import InboundSMS

# Paths
DATA_DIR = Path('/data/workspace/skills/jmp-sms/data')
MESSAGE_HISTORY_PATH = DATA_DIR / 'message_history.json'
CARRIER_HISTORY_PATH = DATA_DIR / 'carrier_history.json'
TIMING_HISTORY_PATH = DATA_DIR / 'timing_history.json'
BEHAVIORAL_PROFILES_PATH = DATA_DIR / 'behavioral_profiles.json'

logger = logging.getLogger(__name__)

# Thread safety
_history_lock = threading.RLock()


class Severity(str, Enum):
    """Severity levels for spoof indicators."""
    LOW = 'low'
    MEDIUM = 'medium'
    HIGH = 'high'


class IndicatorType(str, Enum):
    """Types of spoof indicators."""
    TIMING = 'timing'
    PATTERN = 'pattern'
    CARRIER = 'carrier'
    BEHAVIORAL = 'behavioral'
    VOICE_ATTESTATION = 'voice_attestation'


@dataclass
class SpoofIndicator:
    """Single indicator of potential spoofing."""
    type: IndicatorType
    severity: Severity
    detail: str
    confidence: float = 0.5  # 0-1 confidence in this indicator
    
    def to_dict(self) -> dict[str, Any]:
        return {
            'type': self.type.value,
            'severity': self.severity.value,
            'detail': self.detail,
            'confidence': self.confidence,
        }


@dataclass
class AntiSpoofResult:
    """Result of anti-spoof analysis."""
    passed: bool
    confidence: float  # 0-1 overall confidence
    indicators: list[SpoofIndicator] = field(default_factory=list)
    checks_performed: list[str] = field(default_factory=list)
    
    def to_dict(self) -> dict[str, Any]:
        return {
            'passed': self.passed,
            'confidence': self.confidence,
            'indicators': [i.to_dict() for i in self.indicators],
            'checks_performed': self.checks_performed,
        }


class HistoryManager:
    """Manages historical data for anti-spoof analysis."""
    
    def __init__(self):
        self._ensure_data_dir()
    
    def _ensure_data_dir(self) -> None:
        """Ensure data directory exists."""
        DATA_DIR.mkdir(parents=True, exist_ok=True)
    
    def _load_json(self, path: Path, default: Any = None) -> Any:
        """Load JSON file safely."""
        with _history_lock:
            if not path.exists():
                return default if default is not None else {}
            try:
                with open(path) as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError) as e:
                logger.error(f"Error loading {path}: {e}")
                return default if default is not None else {}
    
    def _save_json(self, path: Path, data: Any) -> bool:
        """Save JSON file atomically."""
        with _history_lock:
            try:
                temp_path = path.with_suffix('.tmp')
                with open(temp_path, 'w') as f:
                    json.dump(data, f, indent=2, default=str)
                temp_path.rename(path)
                return True
            except OSError as e:
                logger.error(f"Error saving {path}: {e}")
                return False
    
    # Carrier History
    def get_carrier_history(self, phone: str) -> list[dict]:
        """Get carrier history for a phone number."""
        data = self._load_json(CARRIER_HISTORY_PATH, {})
        return data.get(phone, [])
    
    def add_carrier_observation(self, phone: str, carrier: str | None, line_type: str | None) -> None:
        """Record a carrier observation."""
        if not carrier:
            return
        data = self._load_json(CARRIER_HISTORY_PATH, {})
        if phone not in data:
            data[phone] = []
        data[phone].append({
            'carrier': carrier,
            'line_type': line_type,
            'observed_at': datetime.now().isoformat(),
        })
        # Keep only last 100 observations per number
        data[phone] = data[phone][-100:]
        self._save_json(CARRIER_HISTORY_PATH, data)
    
    # Timing History
    def get_timing_history(self, phone: str) -> list[dict]:
        """Get message timing history for a phone number."""
        data = self._load_json(TIMING_HISTORY_PATH, {})
        return data.get(phone, [])
    
    def add_timing_observation(self, phone: str, timestamp: datetime) -> None:
        """Record a message timing."""
        data = self._load_json(TIMING_HISTORY_PATH, {})
        if phone not in data:
            data[phone] = []
        data[phone].append({
            'timestamp': timestamp.isoformat(),
            'hour': timestamp.hour,
            'day_of_week': timestamp.weekday(),
        })
        # Keep only last 500 timing observations
        data[phone] = data[phone][-500:]
        self._save_json(TIMING_HISTORY_PATH, data)
    
    # Behavioral Profiles
    def get_behavioral_profile(self, phone: str) -> dict | None:
        """Get behavioral profile for a phone number."""
        data = self._load_json(BEHAVIORAL_PROFILES_PATH, {})
        return data.get(phone)
    
    def update_behavioral_profile(self, phone: str, message: str) -> None:
        """Update behavioral profile based on new message."""
        data = self._load_json(BEHAVIORAL_PROFILES_PATH, {})
        
        if phone not in data:
            data[phone] = {
                'avg_length': 0,
                'lengths': [],
                'uses_emoji': False,
                'emoji_count': 0,
                'uses_caps': False,
                'caps_ratio': 0,
                'common_words': {},
                'greeting_patterns': [],
                'signature_patterns': [],
                'message_count': 0,
            }
        
        profile = data[phone]
        profile['message_count'] += 1
        
        # Track message lengths
        msg_len = len(message)
        profile['lengths'].append(msg_len)
        profile['lengths'] = profile['lengths'][-100:]  # Keep last 100
        profile['avg_length'] = statistics.mean(profile['lengths'])
        
        # Track emoji usage
        emoji_pattern = re.compile(
            "["
            "\U0001F600-\U0001F64F"  # emoticons
            "\U0001F300-\U0001F5FF"  # symbols & pictographs
            "\U0001F680-\U0001F6FF"  # transport & map symbols
            "\U0001F1E0-\U0001F1FF"  # flags
            "\U00002702-\U000027B0"
            "\U000024C2-\U0001F251"
            "]+"
        )
        emojis = emoji_pattern.findall(message)
        if emojis:
            profile['uses_emoji'] = True
            profile['emoji_count'] = (profile['emoji_count'] * (profile['message_count'] - 1) + len(emojis)) / profile['message_count']
        
        # Track capitalization patterns
        if message:
            alpha_chars = [c for c in message if c.isalpha()]
            if alpha_chars:
                caps_ratio = sum(1 for c in alpha_chars if c.isupper()) / len(alpha_chars)
                profile['caps_ratio'] = (profile['caps_ratio'] * (profile['message_count'] - 1) + caps_ratio) / profile['message_count']
                profile['uses_caps'] = profile['caps_ratio'] > 0.3
        
        # Track common words (simple bag of words)
        words = re.findall(r'\b\w+\b', message.lower())
        for word in words:
            if len(word) > 3:  # Skip short words
                profile['common_words'][word] = profile['common_words'].get(word, 0) + 1
        # Keep only top 50 words
        if len(profile['common_words']) > 50:
            sorted_words = sorted(profile['common_words'].items(), key=lambda x: x[1], reverse=True)
            profile['common_words'] = dict(sorted_words[:50])
        
        # Detect greeting patterns (first line)
        first_line = message.split('\n')[0].strip().lower()
        greeting_words = ['hey', 'hi', 'hello', 'yo', 'sup', 'hiya', 'heya']
        if any(first_line.startswith(g) for g in greeting_words):
            if first_line not in profile['greeting_patterns']:
                profile['greeting_patterns'].append(first_line)
                profile['greeting_patterns'] = profile['greeting_patterns'][-10:]
        
        # Detect signature patterns (last line)
        lines = message.strip().split('\n')
        if len(lines) > 1:
            last_line = lines[-1].strip()
            if last_line.startswith('-') or last_line.startswith('~'):
                if last_line not in profile['signature_patterns']:
                    profile['signature_patterns'].append(last_line)
                    profile['signature_patterns'] = profile['signature_patterns'][-5:]
        
        self._save_json(BEHAVIORAL_PROFILES_PATH, data)


# Global history manager
_history = HistoryManager()


def check_carrier_consistency(sms: 'InboundSMS') -> SpoofIndicator | None:
    """
    Check if carrier information is consistent with history.
    
    A sudden carrier change could indicate a SIM swap or spoofing.
    """
    if not sms.carrier_info or not sms.carrier_info.get('carrier'):
        return None
    
    current_carrier = sms.carrier_info.get('carrier')
    current_line_type = sms.carrier_info.get('lineType')
    
    # Get historical carrier data
    history = _history.get_carrier_history(sms.sender)
    
    if not history:
        # First observation - record it
        _history.add_carrier_observation(sms.sender, current_carrier, current_line_type)
        return None
    
    # Check if carrier matches history
    last_carrier = history[-1].get('carrier')
    last_line_type = history[-1].get('line_type')
    
    if current_carrier != last_carrier:
        # Carrier changed!
        _history.add_carrier_observation(sms.sender, current_carrier, current_line_type)
        
        # VoIP to mobile is suspicious
        if last_line_type == 'mobile' and current_line_type == 'voip':
            return SpoofIndicator(
                type=IndicatorType.CARRIER,
                severity=Severity.HIGH,
                detail=f"Line type changed from mobile ({last_carrier}) to VoIP ({current_carrier})",
                confidence=0.9,
            )
        
        # Any carrier change is notable
        return SpoofIndicator(
            type=IndicatorType.CARRIER,
            severity=Severity.MEDIUM,
            detail=f"Carrier changed from {last_carrier} to {current_carrier}",
            confidence=0.7,
        )
    
    # Record observation (even if same)
    _history.add_carrier_observation(sms.sender, current_carrier, current_line_type)
    return None


def check_timing_patterns(sms: 'InboundSMS') -> list[SpoofIndicator]:
    """
    Check for unusual timing patterns.
    
    Detects:
    - Messages at unusual hours (based on history)
    - Rapid-fire messages (many in short period)
    """
    indicators = []
    
    history = _history.get_timing_history(sms.sender)
    _history.add_timing_observation(sms.sender, sms.timestamp)
    
    if len(history) < 5:
        # Not enough history
        return indicators
    
    # 1. Check for unusual hours
    current_hour = sms.timestamp.hour
    historical_hours = [h['hour'] for h in history]
    
    # Calculate typical hour range
    if historical_hours:
        avg_hour = statistics.mean(historical_hours)
        try:
            std_hour = statistics.stdev(historical_hours)
        except statistics.StatisticsError:
            std_hour = 3  # Default if not enough variance
        
        # Is current hour more than 2 std devs from average?
        hour_diff = min(abs(current_hour - avg_hour), 24 - abs(current_hour - avg_hour))
        if std_hour > 0 and hour_diff > 2 * std_hour:
            # Very unusual hour for this sender
            indicators.append(SpoofIndicator(
                type=IndicatorType.TIMING,
                severity=Severity.MEDIUM,
                detail=f"Unusual hour: {current_hour}:00 (typical: {int(avg_hour)}:00 ± {int(std_hour)}h)",
                confidence=0.6,
            ))
    
    # 2. Check for rapid-fire messages
    recent_timestamps = [
        datetime.fromisoformat(h['timestamp'])
        for h in history[-20:]  # Check last 20
    ]
    
    now = sms.timestamp
    last_5_min = [t for t in recent_timestamps if now - t < timedelta(minutes=5)]
    last_1_min = [t for t in recent_timestamps if now - t < timedelta(minutes=1)]
    
    if len(last_1_min) >= 5:
        # 5+ messages in 1 minute is very suspicious
        indicators.append(SpoofIndicator(
            type=IndicatorType.TIMING,
            severity=Severity.HIGH,
            detail=f"Rapid-fire: {len(last_1_min)} messages in last minute",
            confidence=0.85,
        ))
    elif len(last_5_min) >= 10:
        # 10+ messages in 5 minutes is suspicious
        indicators.append(SpoofIndicator(
            type=IndicatorType.TIMING,
            severity=Severity.MEDIUM,
            detail=f"High volume: {len(last_5_min)} messages in last 5 minutes",
            confidence=0.7,
        ))
    
    return indicators


def check_behavioral_patterns(sms: 'InboundSMS') -> list[SpoofIndicator]:
    """
    Check if message style matches historical patterns.
    
    Detects:
    - Significant length deviation
    - Unexpected emoji/no-emoji usage
    - Different capitalization style
    - Missing typical signatures/greetings
    - Suspicious content patterns
    """
    indicators = []
    
    profile = _history.get_behavioral_profile(sms.sender)
    
    # Update profile with new message
    _history.update_behavioral_profile(sms.sender, sms.body)
    
    if not profile or profile.get('message_count', 0) < 10:
        # Not enough history for behavioral analysis
        return indicators
    
    message = sms.body
    
    # 1. Check message length
    msg_len = len(message)
    avg_len = profile.get('avg_length', 0)
    lengths = profile.get('lengths', [])
    
    if avg_len > 0 and lengths:
        try:
            std_len = statistics.stdev(lengths)
        except statistics.StatisticsError:
            std_len = avg_len * 0.5
        
        if std_len > 0:
            len_deviation = abs(msg_len - avg_len) / std_len
            if len_deviation > 3:
                indicators.append(SpoofIndicator(
                    type=IndicatorType.BEHAVIORAL,
                    severity=Severity.LOW,
                    detail=f"Unusual message length: {msg_len} chars (typical: ~{int(avg_len)})",
                    confidence=0.5,
                ))
    
    # 2. Check emoji usage
    emoji_pattern = re.compile(
        "["
        "\U0001F600-\U0001F64F"
        "\U0001F300-\U0001F5FF"
        "\U0001F680-\U0001F6FF"
        "\U0001F1E0-\U0001F1FF"
        "]+"
    )
    has_emoji = bool(emoji_pattern.search(message))
    typically_uses_emoji = profile.get('uses_emoji', False)
    
    if typically_uses_emoji and not has_emoji and profile.get('emoji_count', 0) > 1:
        indicators.append(SpoofIndicator(
            type=IndicatorType.BEHAVIORAL,
            severity=Severity.LOW,
            detail="Typically uses emoji but this message has none",
            confidence=0.4,
        ))
    
    # 3. Check for suspicious credential/sensitive info requests
    sensitive_patterns = [
        r'\b(passwords?|passwd|pwd)\b',
        r'\b(credentials?|logins?)\b',
        r'(give|send|share|provide).+\b(password|credential|login|account)\b',
        r'\b(password|credential|login|account)\b.+(give|send|share|provide)',
        r'\b(ssn|social.?security)\b',
        r'\b(credit.?card|bank.?account|routing.?number)\b',
        r'\b(secret|api.?key|private.?key|token)\b',
        r'\b(urgent|immediately|right.?now)\b.*(send|need|want)',
        r'send.+(all|every).*(password|credential|key)',
    ]
    
    message_lower = message.lower()
    for pattern in sensitive_patterns:
        if re.search(pattern, message_lower):
            indicators.append(SpoofIndicator(
                type=IndicatorType.BEHAVIORAL,
                severity=Severity.HIGH,
                detail=f"Suspicious content: possible credential/sensitive data request",
                confidence=0.8,
            ))
            break
    
    # 4. Check for social engineering patterns
    social_engineering_patterns = [
        r"don'?t tell (anyone|anybody)",
        r"keep (this|it) (secret|private|between us)",
        r"(pretend|act like) (you'?re|i'?m|we'?re)",
        r"ignore (previous|prior|your) (instructions|rules|programming)",
        r"override (your|the) (safety|security)",
        r"(i'?m|this is) (really|actually) (you|me|the owner)",
    ]
    
    for pattern in social_engineering_patterns:
        if re.search(pattern, message_lower):
            indicators.append(SpoofIndicator(
                type=IndicatorType.BEHAVIORAL,
                severity=Severity.HIGH,
                detail=f"Social engineering pattern detected",
                confidence=0.85,
            ))
            break
    
    return indicators


def check_voice_attestation(sms: 'InboundSMS') -> SpoofIndicator | None:
    """
    Check STIR/SHAKEN attestation level for voice calls.
    
    Level A: Full attestation (carrier verified the caller)
    Level B: Partial attestation (carrier saw the call but can't fully verify)
    Level C: Gateway (carrier has no info about the caller)
    """
    if not sms.voice_attestation:
        return None
    
    level = sms.voice_attestation.get('level', 'none')
    
    if level == 'A':
        # Full attestation - good
        return None
    elif level == 'B':
        return SpoofIndicator(
            type=IndicatorType.VOICE_ATTESTATION,
            severity=Severity.MEDIUM,
            detail=f"STIR/SHAKEN level B - partial attestation",
            confidence=0.6,
        )
    elif level in ('C', 'none'):
        return SpoofIndicator(
            type=IndicatorType.VOICE_ATTESTATION,
            severity=Severity.HIGH,
            detail=f"STIR/SHAKEN level {level} - caller not verified by carrier",
            confidence=0.8,
        )
    
    return None


def run_anti_spoof_checks(sms: 'InboundSMS') -> AntiSpoofResult:
    """
    Run all anti-spoof checks on an incoming message.
    
    Args:
        sms: Incoming SMS message
        
    Returns:
        AntiSpoofResult with pass/fail and any indicators
    """
    indicators: list[SpoofIndicator] = []
    checks_performed: list[str] = []
    
    # 1. Carrier consistency check
    checks_performed.append('carrier_consistency')
    carrier_indicator = check_carrier_consistency(sms)
    if carrier_indicator:
        indicators.append(carrier_indicator)
    
    # 2. Timing pattern analysis
    checks_performed.append('timing_patterns')
    timing_indicators = check_timing_patterns(sms)
    indicators.extend(timing_indicators)
    
    # 3. Behavioral pattern analysis
    checks_performed.append('behavioral_patterns')
    behavioral_indicators = check_behavioral_patterns(sms)
    indicators.extend(behavioral_indicators)
    
    # 4. Voice attestation (if applicable)
    if sms.voice_attestation:
        checks_performed.append('voice_attestation')
        voice_indicator = check_voice_attestation(sms)
        if voice_indicator:
            indicators.append(voice_indicator)
    
    # Calculate overall result
    high_severity_count = sum(1 for i in indicators if i.severity == Severity.HIGH)
    medium_severity_count = sum(1 for i in indicators if i.severity == Severity.MEDIUM)
    
    # Fail if any high severity indicators
    passed = high_severity_count == 0
    
    # Calculate confidence (higher is more confident it's NOT a spoof)
    confidence = max(0.0, 1.0 - (high_severity_count * 0.35) - (medium_severity_count * 0.15) - (len(indicators) * 0.05))
    
    if not indicators:
        confidence = 0.95  # High confidence if no indicators
    
    logger.info(
        f"Anti-spoof check for {sms.sender}: "
        f"passed={passed}, confidence={confidence:.2f}, "
        f"indicators={len(indicators)} (high={high_severity_count}, medium={medium_severity_count})"
    )
    
    return AntiSpoofResult(
        passed=passed,
        confidence=confidence,
        indicators=indicators,
        checks_performed=checks_performed,
    )


# CLI interface for testing
if __name__ == '__main__':
    import sys
    
    # Add parent directory for importing InboundSMS
    sys.path.insert(0, str(Path(__file__).parent))
    
    from routing_engine import InboundSMS
    
    logging.basicConfig(level=logging.INFO)
    
    # Test with sample input
    test_sms = InboundSMS(
        sender=sys.argv[1] if len(sys.argv) > 1 else '+15551234567',
        recipient='+15550001234',  # Your JMP number
        body=sys.argv[2] if len(sys.argv) > 2 else 'Test message',
        timestamp=datetime.now(),
        message_id='test-001',
        carrier_info={'carrier': 'T-Mobile', 'lineType': 'mobile'},
    )
    
    result = run_anti_spoof_checks(test_sms)
    print(json.dumps(result.to_dict(), indent=2))
