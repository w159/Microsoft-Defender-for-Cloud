"""§4.3 #5 — Microsoft Graph REST client (httpx) for best-effort owner resolution.

Direct REST against ``https://graph.microsoft.com/v1.0``; do not use ``msgraph-sdk``
(avoids the heavy import and cold-start cost). Token via ``DefaultAzureCredential`` for
``https://graph.microsoft.com/.default``. Retries 429/5xx with exponential backoff
(``tenacity``) and emits OpenTelemetry ``graph.<op>`` spans. Owner resolution is
best-effort: a missing user yields ``None`` rather than an error (§5.2.3).
"""

from __future__ import annotations

import logging
import time
from types import TracebackType
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

import httpx
from opentelemetry import trace
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from models.enrichment import AadUser

if TYPE_CHECKING:
    from azure.core.credentials_async import AsyncTokenCredential

logger = logging.getLogger(__name__)
_tracer = trace.get_tracer(__name__)

_GRAPH_ENDPOINT = "https://graph.microsoft.com/v1.0"
_GRAPH_SCOPE = "https://graph.microsoft.com/.default"
_USER_SELECT = "id,mail,userPrincipalName"

# Refresh the cached token slightly before it actually expires (§5.2).
_TOKEN_REFRESH_SKEW_SECONDS = 300


class GraphClientError(Exception):
    """Raised on unrecoverable Graph failure (§4.3 #5)."""


class _GraphRetryableError(GraphClientError):
    """Internal: a transient Graph failure (429/5xx/timeout) worth retrying (§4.3 #5).

    Subclasses :class:`GraphClientError` so that, once retries are exhausted, the
    error surfaces to callers as a plain ``GraphClientError``.
    """


class GraphClient:
    """§4.3 #5 — async Graph REST client; user resolution is best-effort.

    Async context manager wrapping an ``httpx.AsyncClient``. Acquire a Graph token
    via ``DefaultAzureCredential`` and cache it until expiry; retry 429/5xx via
    ``tenacity``. A user that does not exist resolves to ``None`` (never raises).
    """

    def __init__(
        self,
        *,
        credential: AsyncTokenCredential | None = None,
        endpoint: str = _GRAPH_ENDPOINT,
    ) -> None:
        """Build the client.

        Args:
            credential: An async token credential. Defaults to
                ``azure.identity.aio.DefaultAzureCredential`` so production uses the
                Function's Managed Identity; tests inject a fake (§7).
            endpoint: Graph base endpoint. Overridable for sovereign clouds (§4.3).
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

    async def __aenter__(self) -> GraphClient:
        """Open the underlying ``httpx.AsyncClient`` (§4.3 #5)."""
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
        """Close the ``httpx.AsyncClient`` (§4.3 #5)."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def resolve_user(self, email: str) -> AadUser | None:
        """Resolve a user by email; return ``None`` if not found — never raise (§4.3 #5).

        Args:
            email: The owner email / UPN sourced from a resource tag (§4.3 #5).

        Returns:
            The matching :class:`AadUser`, or ``None`` when the user does not exist
            (a 404 from Graph) — owner resolution is best-effort (§5.2.3).

        Raises:
            GraphClientError: On auth failure, a non-404 client error, or after
                retries are exhausted on a transient (429/5xx/timeout) failure.
        """
        if self._client is None:
            raise GraphClientError("GraphClient must be used as an async context manager")
        if not email:
            return None

        with _tracer.start_as_current_span("graph.resolve_user") as span:
            user = await self._get_user(email)
            span.set_attribute("graph.user_found", user is not None)
            return user

    @retry(
        reraise=True,
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=0.1, max=2.0),
        retry=retry_if_exception_type(_GraphRetryableError),
    )
    async def _get_user(self, email: str) -> AadUser | None:
        """GET one user; retried on 429/5xx/timeout via ``tenacity`` (§4.3 #5)."""
        assert self._client is not None  # guarded by resolve_user(); narrows for mypy
        token = await self._get_token()
        path = f"/users/{quote(email, safe='')}"
        headers = {"Authorization": f"Bearer {token}"}

        try:
            response = await self._client.get(
                path,
                params={"$select": _USER_SELECT},
                headers=headers,
            )
        except httpx.TimeoutException as exc:
            logger.warning("Graph request timed out: %s", exc)
            raise _GraphRetryableError(f"Graph request timed out: {exc}") from exc
        except httpx.HTTPError as exc:
            logger.warning("Graph transport error: %s", exc)
            raise _GraphRetryableError(f"Graph transport error: {exc}") from exc

        status = response.status_code
        if status == 404:
            logger.info("Graph user not found for owner tag (object resolution miss)")
            return None
        if status == 429 or status >= 500:
            logger.warning("Graph returned retryable status %d", status)
            raise _GraphRetryableError(f"Graph returned retryable status {status}")
        if status >= 400:
            raise GraphClientError(f"Graph returned status {status}: {response.text[:500]}")

        payload: dict[str, Any] = response.json()
        return AadUser.model_validate(payload)

    async def _get_token(self) -> str:
        """Return a cached Graph bearer token, refreshing near expiry (§5.2, §7)."""
        now = time.time()
        if self._token is not None and now < self._token_expires_on - _TOKEN_REFRESH_SKEW_SECONDS:
            return self._token
        try:
            access = await self._credential.get_token(_GRAPH_SCOPE)
        except Exception as exc:  # wrap any auth failure uniformly; never retried
            raise GraphClientError(f"failed to acquire Graph token: {exc}") from exc
        self._token = access.token
        self._token_expires_on = float(access.expires_on)
        return self._token
