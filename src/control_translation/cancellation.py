"""Cooperative cancellation primitives for capability execution."""

from __future__ import annotations

from typing import Protocol


class CancellationSignal(Protocol):
    """Minimal signal implemented by ``threading.Event`` and similar tokens."""

    def is_set(self) -> bool: ...


class OperationCancelled(RuntimeError):
    """Raised when an executing capability operation observes cancellation."""


def check_cancelled(signal: CancellationSignal | None) -> None:
    """Stop at a cooperative boundary when cancellation has been requested."""
    if signal is not None and signal.is_set():
        raise OperationCancelled("Capability execution was canceled.")