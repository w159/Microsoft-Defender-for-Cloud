"""§4.7/§6.1 — MDC management-plane client: write a recommendation governance assignment.

Feature B (v2.1 write-back): after a Work Item is created, "assign" the recommendation in
Microsoft Defender for Cloud by PUT-ing a governance assignment whose ``owner`` is a
back-reference to the ADO Work Item. This flips the recommendation to **Assigned** in MDC
and persists the Work Item id in the only writable field MDC exposes — working around the
"no back-reference storage" limitation (§2.4). Auth = the Function's Managed Identity ARM
token (requires Security Admin, §6.1). Retries 429/5xx/timeout with exponential backoff
(``tenacity``) and emits an OpenTelemetry ``mdc.assign_governance`` span.

Read-path enrichment signals (§4.3) remain ARG-served; this client is write-only.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime
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

_ARM_BASE = "https://management.azure.com"
_ARM_SCOPE = "https://management.azure.com/.default"
# 2021-06-01 was retired for governanceAssignments; 2025-05-04 is the current GA version.
_GOVERNANCE_API_VERSION = "2025-05-04"

# Refresh the cached token slightly before it actually expires (§6.1).
_TOKEN_REFRESH_SKEW_SECONDS = 300


class MdcClientError(Exception):
    """Raised on unrecoverable MDC management-plane failure (§5.2)."""


class MdcAssignmentConflictError(MdcClientError):
    """Raised when the assessment already has a governance assignment under a different
    key (HTTP 409). Expected when a human owner is already set; the caller skips the
    write-back rather than clobbering that assignment (§4.7)."""


class _MdcRetryableError(MdcClientError):
    """Internal: a transient MDC failure (429/5xx/timeout) worth retrying (§6.1).

    Subclasses :class:`MdcClientError` so that, once retries are exhausted, the error
    surfaces to callers as a plain ``MdcClientError``.
    """


class MdcClient:
    """§6.1 — async MDC management-plane REST client (Managed Identity ARM auth)."""

    def __init__(self, *, credential: AsyncTokenCredential | None = None) -> None:
        """Build the client.

        Args:
            credential: An async token credential. Defaults to
                ``azure.identity.aio.DefaultAzureCredential`` so production uses the
                Function's Managed Identity; tests inject a fake (§6.1, §7).
        """
        if credential is None:
            # Imported lazily to keep cold-start cost off the module import path (§5.2).
            from azure.identity.aio import DefaultAzureCredential

            credential = DefaultAzureCredential()
        self._credential: AsyncTokenCredential = credential
        self._client: httpx.AsyncClient | None = None
        self._token: str | None = None
        self._token_expires_on: float = 0.0

    async def __aenter__(self) -> MdcClient:
        """Open the underlying ``httpx.AsyncClient`` (§5.2, §6.1)."""
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(connect=5.0, read=15.0, write=15.0, pool=5.0),
        )
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        """Close the ``httpx.AsyncClient`` (§5.2)."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def assign_governance(
        self,
        assessment_id: str,
        assignment_key: str,
        *,
        owner: str,
        remediation_due_date: datetime,
    ) -> None:
        """§4.7 — PUT a governance assignment on the assessment (sets it Assigned).

        Args:
            assessment_id: The assessment ARM resource id
                (``/subscriptions/.../providers/Microsoft.Security/assessments/<key>``).
            assignment_key: A deterministic GUID so repeated calls upsert the same
                assignment rather than creating duplicates.
            owner: The Work Item back-reference (e.g. ``ado-wi-42@<domain>``).
            remediation_due_date: Advisory remediation due date (``isGracePeriod``).
        """
        url = (
            f"{_ARM_BASE}{assessment_id}/governanceAssignments/{assignment_key}"
            f"?api-version={_GOVERNANCE_API_VERSION}"
        )
        body = {
            "properties": {
                "owner": owner,
                "remediationDueDate": remediation_due_date.isoformat(),
                "isGracePeriod": True,
            }
        }
        with _tracer.start_as_current_span("mdc.assign_governance"):
            await self._request("PUT", url, json_body=body)

    @retry(
        reraise=True,
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=0.1, max=2.0),
        retry=retry_if_exception_type(_MdcRetryableError),
    )
    async def _request(self, method: str, url: str, *, json_body: Any = None) -> httpx.Response:
        """Send one MDC ARM request; retry 429/5xx/timeout via ``tenacity`` (§6.1)."""
        assert self._client is not None  # guarded by callers; narrows for mypy
        token = await self._get_token()
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

        try:
            response = await self._client.request(method, url, json=json_body, headers=headers)
        except httpx.TimeoutException as exc:
            logger.warning("MDC request timed out: %s", exc)
            raise _MdcRetryableError(f"MDC request timed out: {exc}") from exc
        except httpx.HTTPError as exc:
            logger.warning("MDC transport error: %s", exc)
            raise _MdcRetryableError(f"MDC transport error: {exc}") from exc

        status = response.status_code
        if status == 429 or status >= 500:
            logger.warning("MDC returned retryable status %d", status)
            raise _MdcRetryableError(f"MDC returned retryable status {status}")
        if status == 409:
            # The assessment already has a governance assignment under another key
            # (e.g. a human owner). Surface a distinct, non-retryable error so the
            # caller can skip without clobbering it (§4.7).
            raise MdcAssignmentConflictError(
                f"governance assignment already exists: {response.text[:300]}"
            )
        if status >= 400:
            raise MdcClientError(f"MDC returned status {status}: {response.text[:500]}")

        return response

    async def _get_token(self) -> str:
        """Return a cached ARM bearer token, refreshing near expiry (§6.1, §7)."""
        now = time.time()
        if self._token is not None and now < self._token_expires_on - _TOKEN_REFRESH_SKEW_SECONDS:
            return self._token
        try:
            access = await self._credential.get_token(_ARM_SCOPE)
        except Exception as exc:  # wrap any auth failure uniformly; never retried
            raise MdcClientError(f"failed to acquire ARM token: {exc}") from exc
        self._token = access.token
        self._token_expires_on = float(access.expires_on)
        return self._token
