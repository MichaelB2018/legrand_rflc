"""Tests that key material from the vendored hub library never reaches logs."""

from __future__ import annotations

import logging
from unittest.mock import AsyncMock, MagicMock

import pytest

from custom_components.legrand_rflc.hub import (
    REDACTED,
    Authenticator,
    _redact_frame,
    hash_password,
)

HUB_LOGGER = "custom_components.legrand_rflc.hub"
KEY = hash_password(b"secret")


def _authenticator() -> Authenticator:
    authenticator = Authenticator(key=KEY)
    authenticator._writer = MagicMock(drain=AsyncMock())
    return authenticator


async def test_send_keys_redacted_from_log(caplog: pytest.LogCaptureFixture) -> None:
    """The Keys property is sent to the hub but masked in the debug log."""
    caplog.set_level(logging.DEBUG, logger=HUB_LOGGER)
    authenticator = _authenticator()
    message = authenticator.compose_keys(hash_password(b""), KEY)
    keys = message[Authenticator.PROPERTY_LIST][Authenticator.KEYS]

    await authenticator.send(message)

    assert keys.encode() in authenticator._writer.write.call_args[0][0]
    assert keys not in caplog.text
    assert REDACTED in caplog.text


async def test_send_without_writer_redacts_keys(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The warning logged when no connection exists also masks Keys."""
    authenticator = Authenticator(key=KEY)
    message = authenticator.compose_keys(hash_password(b""), KEY)
    keys = message[Authenticator.PROPERTY_LIST][Authenticator.KEYS]

    await authenticator.send(message)

    assert keys not in caplog.text
    assert REDACTED in caplog.text


async def test_challenge_response_redacted_from_log(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The response to the hub's challenge is not logged."""
    caplog.set_level(logging.DEBUG, logger=HUB_LOGGER)
    authenticator = _authenticator()
    challenge = bytes(range(16))

    await authenticator._send_challenge_response(KEY, challenge)

    response = Authenticator._encrypt(KEY, challenge).hex()
    authenticator._writer.write.assert_called_once_with(response.encode())
    assert response not in caplog.text


def test_redact_received_frame() -> None:
    """A Keys value in a received frame is masked for logging."""
    frame = b'{"Service":"SystemPropertiesChanged","PropertyList":{"Keys": "abc123"}}'
    assert _redact_frame(frame) == (
        '{"Service":"SystemPropertiesChanged","PropertyList":{"Keys": "'
        + REDACTED
        + '"}}'
    )
