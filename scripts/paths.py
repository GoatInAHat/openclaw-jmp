"""Portable filesystem locations for the OpenClaw JMP skill.

Runtime state and credentials live outside the installed skill directory so
ClawHub updates cannot overwrite them. Every location can be overridden for
containers and tests.
"""

from __future__ import annotations

import os
from pathlib import Path


def _env_path(name: str, default: Path) -> Path:
    value = os.environ.get(name)
    return Path(value).expanduser() if value else default


SKILL_DIR = Path(__file__).resolve().parents[1]
OPENCLAW_HOME = _env_path("OPENCLAW_HOME", Path.home() / ".openclaw")
CONFIG_DIR = _env_path("OPENCLAW_JMP_CONFIG_DIR", OPENCLAW_HOME / "openclaw-jmp")
DATA_DIR = _env_path("OPENCLAW_JMP_DATA_DIR", OPENCLAW_HOME / "state" / "openclaw-jmp")
CREDENTIALS_PATH = _env_path("JMP_CREDENTIALS_PATH", CONFIG_DIR / "credentials.json")
MESSAGE_LOG_PATH = _env_path("OPENCLAW_JMP_MESSAGE_LOG", DATA_DIR / "message_history.jsonl")
AUDIT_DIR = _env_path("OPENCLAW_JMP_AUDIT_DIR", DATA_DIR / "audit")
