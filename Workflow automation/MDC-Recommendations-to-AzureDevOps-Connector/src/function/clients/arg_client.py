"""§4.3/§4.4 — Azure Resource Graph REST client (httpx, Managed Identity auth).

No management-plane SDKs: queries the ARG ``resources``/``securityresources`` tables
directly over REST. Token via ``DefaultAzureCredential`` for the ARM resource. Retries
429/5xx with exponential backoff (``tenacity``), respects the ARG throttle (15 queries /
5 sec / user), and emits OpenTelemetry ``arg.<op>`` spans.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import deque
from types import TracebackType
from typing import TYPE_CHECKING, Any

import httpx
from opentelemetry import trace
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

if TYPE_CHECKING:
    from azure.core.credentials_async import AsyncTokenCredential

logger = logging.getLogger(__name__)
_tracer = trace.get_tracer(__name__)

_ARM_ENDPOINT = "https://management.azure.com"
_ARG_PATH = "/providers/Microsoft.ResourceGraph/resources"
_ARG_API_VERSION = "2022-10-01"
_ARM_SCOPE = "https://management.azure.com/.default"

# Refresh the cached token slightly before it actually expires (§5.2).
_TOKEN_REFRESH_SKEW_SECONDS = 300

# ARG throttle: 15 queries per 5 seconds per user (§4.3).
_THROTTLE_MAX_QUERIES = 15
_THROTTLE_WINDOW_SECONDS = 5.0

# ARG paginates large result sets; page size cap per request.
_ARG_PAGE_SIZE = 1000


class ArgClientError(Exception):
    """Raised on unrecoverable ARG query failure (§4.3)."""


class _ArgRetryableError(ArgClientError):
    """Internal: a transient ARG failure (429/5xx/timeout) worth retrying (§4.3).

    Subclasses :class:`ArgClientError` so that, once retries are exhausted, the
    error surfaces to callers as a plain ``ArgClientError``.
    """


class ArgClient:
    """§4.3 — async client for the ARG REST endpoint.

    Async context manager wrapping an ``httpx.AsyncClient``. Respect the ARG
    throttle (15 queries / 5 sec / user) and retry 429/5xx via ``tenacity``.
    Acquire an ARM token via ``DefaultAzureCredential`` and cache it until expiry.
    """

    def __init__(
        self,
        *,
        credential: AsyncTokenCredential | None = None,
        endpoint: str = _ARM_ENDPOINT,
    ) -> None:
        """Build the client.

        Args:
            credential: An async token credential. Defaults to
                ``azure.identity.aio.DefaultAzureCredential`` so production uses the
                Function's Managed Identity; tests inject a fake (§7).
            endpoint: ARM base endpoint. Overridable for sovereign clouds (§4.3).
        """
        if credential is None:
            # Imported lazily to keep cold-start cost off the module import path (§5.2).
            from azure.identity.aio import DefaultAzureCredential

            credential = DefaultAzureCredential()
        self._credential: AsyncTokenCredential = credential
        self._endpoint = endpoint.rstrip("/")
        self._client: httpx.AsyncClient | None = None
        self._token: str | None = None
        self._token_expires_on: float = 0.0
        self._throttle_times: deque[float] = deque()
        self._throttle_lock = asyncio.Lock()

    async def __aenter__(self) -> ArgClient:
        """Open the underlying ``httpx.AsyncClient`` (§4.3, §5.2)."""
        self._client = httpx.AsyncClient(
            base_url=self._endpoint,
            timeout=httpx.Timeout(connect=5.0, read=15.0, write=15.0, pool=5.0),
        )
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        """Close the ``httpx.AsyncClient`` (§4.3)."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def query(self, kql: str, subscriptions: list[str]) -> list[dict[str, Any]]:
        """Run a single ARG query and return the rows (§4.3, §4.4).

        Args:
            kql: The KQL query (build fragments with ``arg_queries``).
            subscriptions: Subscription scope for the query.

        Returns:
            All result rows as dictionaries, following ``$skipToken`` pagination.

        Raises:
            ArgClientError: On auth failure, a non-retryable HTTP error, or after
                retries are exhausted on a transient (429/5xx/timeout) failure.
        """
        if self._client is None:
            raise ArgClientError("ArgClient must be used as an async context manager")
        if not subscriptions:
            raise ArgClientError("query requires at least one subscription")

        with _tracer.start_as_current_span("arg.query") as span:
            span.set_attribute("arg.subscription_count", len(subscriptions))

            rows: list[dict[str, Any]] = []
            skip_token: str | None = None
            page_count = 0
            while True:
                token = await self._get_token()
                payload = await self._post_page(kql, subscriptions, token, skip_token)
                page_count += 1
                rows.extend(payload.get("data", []))
                skip_token = payload.get("$skipToken")
                if not skip_token:
                    break

            span.set_attribute("arg.row_count", len(rows))
            span.set_attribute("arg.page_count", page_count)
            logger.debug("ARG query returned %d rows across %d page(s)", len(rows), page_count)
            return rows

    @retry(
        reraise=True,
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=0.1, max=2.0),
        retry=retry_if_exception_type(_ArgRetryableError),
    )
    async def _post_page(
        self,
        kql: str,
        subscriptions: list[str],
        token: str,
        skip_token: str | None,
    ) -> dict[str, Any]:
        """POST one ARG page; retried on 429/5xx/timeout via ``tenacity`` (§4.3)."""
        assert self._client is not None  # guarded by query(); narrows for mypy
        await self._throttle()

        options: dict[str, Any] = {"resultFormat": "objectArray", "$top": _ARG_PAGE_SIZE}
        if skip_token:
            options["$skipToken"] = skip_token
        body = {"subscriptions": subscriptions, "query": kql, "options": options}
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

        try:
            response = await self._client.post(
                f"{_ARG_PATH}?api-version={_ARG_API_VERSION}",
                json=body,
                headers=headers,
            )
        except httpx.TimeoutException as exc:
            logger.warning("ARG request timed out: %s", exc)
            raise _ArgRetryableError(f"ARG request timed out: {exc}") from exc
        except httpx.HTTPError as exc:
            logger.warning("ARG transport error: %s", exc)
            raise _ArgRetryableError(f"ARG transport error: {exc}") from exc

        status = response.status_code
        if status == 429 or status >= 500:
            logger.warning("ARG returned retryable status %d", status)
            raise _ArgRetryableError(f"ARG returned retryable status {status}")
        if status >= 400:
            raise ArgClientError(f"ARG returned status {status}: {response.text[:500]}")

        result: dict[str, Any] = response.json()
        return result

    async def _get_token(self) -> str:
        """Return a cached ARM bearer token, refreshing near expiry (§5.2, §7)."""
        now = time.time()
        if self._token is not None and now < self._token_expires_on - _TOKEN_REFRESH_SKEW_SECONDS:
            return self._token
        try:
            access = await self._credential.get_token(_ARM_SCOPE)
        except Exception as exc:  # wrap any auth failure uniformly; never retried
            raise ArgClientError(f"failed to acquire ARM token: {exc}") from exc
        self._token = access.token
        self._token_expires_on = float(access.expires_on)
        return self._token

    async def _throttle(self) -> None:
        """Block until issuing a query respects 15 queries / 5 sec (§4.3)."""
        async with self._throttle_lock:
            loop = asyncio.get_running_loop()
            now = loop.time()
            self._purge_throttle(now)
            if len(self._throttle_times) >= _THROTTLE_MAX_QUERIES:
                sleep_for = _THROTTLE_WINDOW_SECONDS - (now - self._throttle_times[0])
                if sleep_for > 0:
                    logger.debug("ARG throttle: sleeping %.3fs", sleep_for)
                    await asyncio.sleep(sleep_for)
                now = loop.time()
                self._purge_throttle(now)
            self._throttle_times.append(now)

    def _purge_throttle(self, now: float) -> None:
        """Drop throttle timestamps older than the sliding window (§4.3)."""
        while self._throttle_times and now - self._throttle_times[0] >= _THROTTLE_WINDOW_SECONDS:
            self._throttle_times.popleft()
