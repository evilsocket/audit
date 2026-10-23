"""Tests for the API-error classification in runner.py."""

from __future__ import annotations

import pytest

from audit.runner import (
    PromptTooLongError,
    QuotaExhaustedError,
    TransientAgentError,
    _classify_api_error,
)


@pytest.mark.parametrize("text", [
    "You're out of extra usage · resets 2am (Europe/Rome)",
    "Usage limit reached for the day.",
    "Your plan has no remaining quota.",
    "YOU'RE OUT OF EXTRA USAGE.",
    "You've hit your session limit · resets 5:10am (UTC)",
    "You've hit your session limit · resets 11pm",
])
def test_quota_classified(text: str) -> None:
    label, exc = _classify_api_error(text)
    assert label == "quota_exhausted"
    assert exc is QuotaExhaustedError


@pytest.mark.parametrize("text", [
    "API Error: 529 Overloaded. This is a server-side issue, usually temporary",
    "Server overloaded — please try again",
    "API Error: 503",
    "API Error: 502 Bad Gateway",
    "API Error: 500 Internal Server Error",
    "rate_limit hit",
    "Service temporarily unavailable",
])
def test_transient_classified(text: str) -> None:
    label, exc = _classify_api_error(text)
    assert label == "transient"
    assert exc is TransientAgentError


def test_unknown_defaults_to_transient() -> None:
    label, exc = _classify_api_error("some weird new error string")
    assert label == "unknown_api_error"
    assert exc is TransientAgentError


def test_empty_defaults_to_transient() -> None:
    label, exc = _classify_api_error("")
    assert label == "unknown_api_error"
    assert exc is TransientAgentError


def test_prompt_too_long_not_retried() -> None:
    label, exc = _classify_api_error("Prompt is too long")
    assert label == "prompt_too_long"
    assert exc is PromptTooLongError
    assert not issubclass(exc, TransientAgentError)
