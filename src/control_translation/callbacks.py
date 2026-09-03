"""Durable terminal callback validation and asynchronous delivery."""

from __future__ import annotations

import json
import logging
import random
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from collections.abc import Callable
from typing import Mapping, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from pydantic import BaseModel, ConfigDict


logger = logging.getLogger(__name__)

CALLBACK_SIGNAL = "janus.capability-completion.v1"
CALLBACK_CAPABILITY = "control-translation"
RETRYABLE_STATUS_CODES = {408, 425, 429, 500, 502, 503, 504}
CONFIGURATION_FAILURE_STATUS_CODES = {400, 401, 404, 415}
RETRY_DELAYS_SECONDS = (5, 15, 30, 60, 300)
STEADY_RETRY_DELAY_SECONDS = 900


class CallbackValidationError(ValueError):
    """Raised when callback submission headers are incomplete or unsafe."""


@dataclass(frozen=True)
class CallbackMetadata:
    callback_url: str
    callback_workflow_id: str
    callback_signal: str


@dataclass(frozen=True)
class CallbackDelivery:
    event_id: str
    callback_url: str
    callback_workflow_id: str
    callback_signal: str
    capability: str
    request_id: str
    correlation_id: str
    run_id: str
    terminal_status: str
    attempts: int
    next_attempt_at: datetime


class CallbackWakeup(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str
    capability: str
    request_id: str
    correlation_id: str
    run_id: str


class CallbackPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    workflow_id: str
    wakeup: CallbackWakeup


@dataclass(frozen=True)
class CallbackHttpResponse:
    status_code: int
    body: bytes
    headers: Mapping[str, str]


class CallbackTransportError(RuntimeError):
    """Raised for retryable network failures without exposing request secrets."""


class CallbackHttpClient(Protocol):
    def post_json(
        self,
        url: str,
        payload: bytes,
        *,
        token: str,
        timeout_seconds: float,
    ) -> CallbackHttpResponse: ...


class CallbackRepository(Protocol):
    def list_due_callback_deliveries(
        self,
        *,
        now: datetime,
        limit: int,
    ) -> tuple[CallbackDelivery, ...]: ...

    def mark_callback_delivered(
        self,
        event_id: str,
        *,
        delivered_at: datetime,
        status_code: int,
    ) -> None: ...

    def reschedule_callback_delivery(
        self,
        event_id: str,
        *,
        attempts: int,
        next_attempt_at: datetime,
        status_code: int | None,
        error_category: str,
    ) -> None: ...

    def mark_callback_configuration_failed(
        self,
        event_id: str,
        *,
        attempts: int,
        failed_at: datetime,
        status_code: int | None,
        error_category: str,
    ) -> None: ...


class UrllibCallbackHttpClient:
    """Small standard-library HTTP client with bounded response reads."""

    def post_json(
        self,
        url: str,
        payload: bytes,
        *,
        token: str,
        timeout_seconds: float,
    ) -> CallbackHttpResponse:
        request = Request(
            url,
            data=payload,
            method="POST",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
        )
        try:
            with urlopen(request, timeout=timeout_seconds) as response:
                return CallbackHttpResponse(
                    status_code=response.status,
                    body=response.read(65_536),
                    headers=dict(response.headers.items()),
                )
        except HTTPError as exc:
            return CallbackHttpResponse(
                status_code=exc.code,
                body=exc.read(65_536),
                headers=dict(exc.headers.items()) if exc.headers else {},
            )
        except (TimeoutError, URLError, OSError) as exc:
            raise CallbackTransportError(type(exc).__name__) from exc


def callback_metadata_from_headers(
    headers: Mapping[str, str],
    *,
    allowed_hosts: tuple[str, ...] = (),
) -> CallbackMetadata | None:
    """Validate the all-or-none callback header group."""
    normalized_headers = {key.lower(): value for key, value in headers.items()}
    callback_url = normalized_headers.get("x-janus-callback-url")
    workflow_id = normalized_headers.get("x-janus-callback-workflow-id")
    callback_signal = normalized_headers.get("x-janus-callback-signal")
    values = (callback_url, workflow_id, callback_signal)
    if all(value is None for value in values):
        return None
    if any(value is None or not value.strip() for value in values):
        raise CallbackValidationError(
            "Callback headers must include URL, workflow ID, and signal together."
        )

    assert callback_url is not None
    assert workflow_id is not None
    assert callback_signal is not None
    callback_url = callback_url.strip()
    workflow_id = workflow_id.strip()
    callback_signal = callback_signal.strip()
    parsed = urlsplit(callback_url)
    if (
        parsed.scheme.lower() != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise CallbackValidationError(
            "Callback URL must be an HTTPS URL without credentials or a fragment."
        )
    if len(callback_url) > 2048:
        raise CallbackValidationError("Callback URL is too long.")
    if len(workflow_id) > 255:
        raise CallbackValidationError("Callback workflow ID is too long.")
    normalized_allowed_hosts = {host.strip().lower() for host in allowed_hosts if host.strip()}
    if normalized_allowed_hosts and parsed.hostname.lower() not in normalized_allowed_hosts:
        raise CallbackValidationError("Callback URL hostname is not allowlisted.")
    if callback_signal != CALLBACK_SIGNAL:
        raise CallbackValidationError(
            f"Callback signal must be exactly '{CALLBACK_SIGNAL}'."
        )
    return CallbackMetadata(
        callback_url=callback_url,
        callback_workflow_id=workflow_id,
        callback_signal=callback_signal,
    )


def callback_event_id(run_id: str) -> str:
    return f"{CALLBACK_CAPABILITY}:{run_id}:terminal:v1"


def callback_terminal_status(result_status: str) -> str:
    return "failed" if result_status == "malfunction" else "completed"


def callback_payload(delivery: CallbackDelivery) -> CallbackPayload:
    return CallbackPayload(
        workflow_id=delivery.callback_workflow_id,
        wakeup=CallbackWakeup(
            event_id=delivery.event_id,
            capability=delivery.capability,
            request_id=delivery.request_id,
            correlation_id=delivery.correlation_id,
            run_id=delivery.run_id,
        ),
    )


class CallbackDispatcher:
    """Deliver durable outbox records independently of result availability."""

    def __init__(
        self,
        repository: CallbackRepository | Callable[[], CallbackRepository],
        *,
        token: str | None,
        timeout_seconds: float = 10.0,
        poll_interval_seconds: float = 1.0,
        batch_size: int = 25,
        http_client: CallbackHttpClient | None = None,
        jitter: Callable[[], float] | None = None,
    ) -> None:
        self._repository_provider = (
            repository if callable(repository) else lambda: repository
        )
        self._token = token
        self._timeout_seconds = timeout_seconds
        self._poll_interval_seconds = poll_interval_seconds
        self._batch_size = batch_size
        self._http_client = http_client or UrllibCallbackHttpClient()
        self._jitter = jitter or (lambda: random.uniform(0.8, 1.2))
        self._stop_event = threading.Event()
        self._wake_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run,
            name="control-translation-callback-dispatcher",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        self._wake_event.set()
        if self._thread is not None:
            self._thread.join(timeout=max(1.0, self._timeout_seconds + 1.0))
        self._thread = None

    def wake(self) -> None:
        self._wake_event.set()

    def _run(self) -> None:
        while not self._stop_event.is_set():
            try:
                self.deliver_due()
            except Exception:
                logger.exception("Callback dispatcher iteration failed")
            self._wake_event.wait(self._poll_interval_seconds)
            self._wake_event.clear()

    def deliver_due(self, *, now: datetime | None = None) -> int:
        current_time = now or datetime.now(timezone.utc)
        deliveries = self._repository_provider().list_due_callback_deliveries(
            now=current_time,
            limit=self._batch_size,
        )
        for delivery in deliveries:
            self._deliver(delivery, now=current_time)
        return len(deliveries)

    def _deliver(self, delivery: CallbackDelivery, *, now: datetime) -> None:
        attempts = delivery.attempts + 1
        if not self._token:
            logger.error(
                "Callback delivery configuration alert event_id=%s run_id=%s "
                "reason=missing-callback-token",
                delivery.event_id,
                delivery.run_id,
            )
            self._repository_provider().mark_callback_configuration_failed(
                delivery.event_id,
                attempts=attempts,
                failed_at=now,
                status_code=None,
                error_category="missing-callback-token",
            )
            return

        payload = callback_payload(delivery).model_dump_json().encode("utf-8")
        try:
            response = self._http_client.post_json(
                delivery.callback_url,
                payload,
                token=self._token,
                timeout_seconds=self._timeout_seconds,
            )
        except CallbackTransportError as exc:
            self._retry(
                delivery,
                attempts=attempts,
                now=now,
                status_code=None,
                error_category=f"network-{str(exc).lower()}",
                retry_after=None,
            )
            return

        if response.status_code == 202 and _accepted_response(
            response.body, delivery.event_id
        ):
            self._repository_provider().mark_callback_delivered(
                delivery.event_id,
                delivered_at=now,
                status_code=response.status_code,
            )
            logger.info(
                "Callback delivery accepted event_id=%s run_id=%s attempts=%s",
                delivery.event_id,
                delivery.run_id,
                attempts,
            )
            return

        if response.status_code in RETRYABLE_STATUS_CODES or response.status_code == 202:
            self._retry(
                delivery,
                attempts=attempts,
                now=now,
                status_code=response.status_code,
                error_category=(
                    "invalid-accepted-response"
                    if response.status_code == 202
                    else "retryable-http-status"
                ),
                retry_after=_retry_after(response.headers, now),
            )
            return

        error_category = (
            "callback-configuration-http-status"
            if response.status_code in CONFIGURATION_FAILURE_STATUS_CODES
            else "non-retryable-http-status"
        )
        self._repository_provider().mark_callback_configuration_failed(
            delivery.event_id,
            attempts=attempts,
            failed_at=now,
            status_code=response.status_code,
            error_category=error_category,
        )
        logger.error(
            "Callback delivery configuration alert event_id=%s run_id=%s "
            "status_code=%s reason=%s",
            delivery.event_id,
            delivery.run_id,
            response.status_code,
            error_category,
        )

    def _retry(
        self,
        delivery: CallbackDelivery,
        *,
        attempts: int,
        now: datetime,
        status_code: int | None,
        error_category: str,
        retry_after: float | None,
    ) -> None:
        delay_seconds = retry_after
        if delay_seconds is None:
            schedule_index = min(attempts - 1, len(RETRY_DELAYS_SECONDS))
            base_delay = (
                RETRY_DELAYS_SECONDS[schedule_index]
                if schedule_index < len(RETRY_DELAYS_SECONDS)
                else STEADY_RETRY_DELAY_SECONDS
            )
            delay_seconds = max(0.0, base_delay * float(self._jitter()))
        next_attempt_at = now + timedelta(seconds=delay_seconds)
        self._repository_provider().reschedule_callback_delivery(
            delivery.event_id,
            attempts=attempts,
            next_attempt_at=next_attempt_at,
            status_code=status_code,
            error_category=error_category,
        )
        logger.warning(
            "Callback delivery scheduled for retry event_id=%s run_id=%s "
            "attempts=%s status_code=%s next_attempt_at=%s reason=%s",
            delivery.event_id,
            delivery.run_id,
            attempts,
            status_code or "-",
            next_attempt_at.isoformat(),
            error_category,
        )

def _accepted_response(body: bytes, expected_event_id: str) -> bool:
    try:
        payload = json.loads(body)
    except (TypeError, ValueError):
        return False
    return (
        isinstance(payload, dict)
        and set(payload) == {"event_id", "status"}
        and payload.get("event_id") == expected_event_id
        and payload.get("status") == "accepted"
    )


def _retry_after(headers: Mapping[str, str], now: datetime) -> float | None:
    value = next(
        (header_value for name, header_value in headers.items() if name.lower() == "retry-after"),
        None,
    )
    if value is None:
        return None
    try:
        return max(0.0, float(value.strip()))
    except ValueError:
        try:
            retry_at = parsedate_to_datetime(value)
        except (TypeError, ValueError, OverflowError):
            return None
        if retry_at.tzinfo is None:
            retry_at = retry_at.replace(tzinfo=timezone.utc)
        return max(0.0, (retry_at - now).total_seconds())
