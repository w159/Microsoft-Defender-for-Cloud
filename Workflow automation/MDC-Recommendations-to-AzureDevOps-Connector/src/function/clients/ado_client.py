"""§4.4/§5.2/§6.1 — Azure DevOps REST client (httpx, Managed Identity Entra token).

No PAT, no Key Vault. Acquire an Entra token for the ADO resource
``499b84ac-1321-427f-aa17-267ca6975798/.default`` via ``DefaultAzureCredential``;
cache until expiry and refresh on 401. Uses the JSON Patch format ADO requires.
Retries 429/5xx/401/timeout with exponential backoff (``tenacity``) and emits
OpenTelemetry ``ado.<op>`` spans.
"""

from __future__ import annotations

import logging
import os
import time
from datetime import date, datetime
from types import TracebackType
from typing import TYPE_CHECKING, Any, Literal
from urllib.parse import quote

import httpx
from opentelemetry import trace
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from models.briefing import WorkItemResult

if TYPE_CHECKING:
    from azure.core.credentials_async import AsyncTokenCredential

logger = logging.getLogger(__name__)
_tracer = trace.get_tracer(__name__)

_ADO_RESOURCE_ID = "499b84ac-1321-427f-aa17-267ca6975798"
_API_VERSION = "7.1"
_COMMENTS_API_VERSION = "7.1-preview.4"
_DEFAULT_WORK_ITEM_TYPE = "Security Recommendation"
_JSON_PATCH_CONTENT_TYPE = "application/json-patch+json"
_WORK_ITEM_TYPE_FIELD = "System.WorkItemType"

# Refresh the cached token slightly before it actually expires (§6.1).
_TOKEN_REFRESH_SKEW_SECONDS = 300


class AdoClientError(Exception):
    """Raised on unrecoverable ADO API failure (§5.2)."""


class _AdoRetryableError(AdoClientError):
    """Internal: a transient ADO failure (401/429/5xx/timeout) worth retrying (§6.1).

    Subclasses :class:`AdoClientError` so that, once retries are exhausted, the
    error surfaces to callers as a plain ``AdoClientError``. A 401 is retryable
    because the cached Entra token is invalidated first, forcing a refresh (§6.1).
    """


class AdoClient:
    """§5.2/§6.1 — async Azure DevOps REST client (Managed Identity auth)."""

    def __init__(
        self,
        *,
        organization_url: str | None = None,
        project: str | None = None,
        credential: AsyncTokenCredential | None = None,
        resource_id: str = _ADO_RESOURCE_ID,
    ) -> None:
        """Build the client.

        Args:
            organization_url: ADO org URL (e.g. ``https://dev.azure.com/org``).
                Defaults to the ``ADO_ORG_URL`` app setting.
            project: ADO project name. Defaults to the ``ADO_PROJECT`` app setting.
            credential: An async token credential. Defaults to
                ``azure.identity.aio.DefaultAzureCredential`` so production uses the
                Function's Managed Identity; tests inject a fake (§6.1, §7).
            resource_id: ADO Entra application id used to scope the token (§6.1).
        """
        if credential is None:
            # Imported lazily to keep cold-start cost off the module import path (§5.2).
            from azure.identity.aio import DefaultAzureCredential

            credential = DefaultAzureCredential()
        self._credential: AsyncTokenCredential = credential
        self._org_url = (organization_url or os.environ.get("ADO_ORG_URL", "")).rstrip("/")
        self._project = project or os.environ.get("ADO_PROJECT", "")
        self._scope = f"{resource_id}/.default"
        self._client: httpx.AsyncClient | None = None
        self._token: str | None = None
        self._token_expires_on: float = 0.0

    async def __aenter__(self) -> AdoClient:
        """Open the underlying ``httpx.AsyncClient`` (§5.2, §6.1)."""
        if not self._org_url or not self._project:
            raise AdoClientError("ADO_ORG_URL and ADO_PROJECT must be configured")
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

    async def query_wiql(self, query: str) -> list[int]:
        """Run a WIQL query; return the matching work-item ids (§5.2).

        Used by the dedupe lookup keyed on ``Custom.MDCAssessmentId`` +
        ``Custom.MDCResourceId`` (§5.2.4).
        """
        url = self._url("_apis/wit/wiql", _API_VERSION)
        with _tracer.start_as_current_span("ado.query_wiql"):
            response = await self._request("POST", url, json_body={"query": query})
            data: dict[str, Any] = response.json()
            return [int(item["id"]) for item in data.get("workItems", [])]

    async def get_work_item(self, id: int) -> dict[str, Any]:
        """Fetch a single work item (id, url, links, fields) (§5.2.5).

        Used by update-churn control to read the stored ``Custom.MaterialHash``
        before deciding whether a PATCH is warranted.
        """
        url = self._url(f"_apis/wit/workitems/{id}", _API_VERSION)
        with _tracer.start_as_current_span("ado.get_work_item"):
            response = await self._request("GET", url)
            data: dict[str, Any] = response.json()
            return data

    async def create_work_item(self, fields: dict[str, Any]) -> WorkItemResult:
        """Create a work item from a field map (§4.4)."""
        work_item_type = str(fields.get(_WORK_ITEM_TYPE_FIELD) or _DEFAULT_WORK_ITEM_TYPE)
        patch = self._build_patch({k: v for k, v in fields.items() if k != _WORK_ITEM_TYPE_FIELD})
        url = self._url(f"_apis/wit/workitems/${quote(work_item_type, safe='')}", _API_VERSION)
        with _tracer.start_as_current_span("ado.create_work_item"):
            response = await self._request(
                "POST", url, json_body=patch, content_type=_JSON_PATCH_CONTENT_TYPE
            )
            return self._to_result(response.json(), action="created")

    async def update_work_item(self, id: int, fields: dict[str, Any]) -> WorkItemResult:
        """Update a work item; churn is controlled by the caller (§5.2.5)."""
        patch = self._build_patch({k: v for k, v in fields.items() if k != _WORK_ITEM_TYPE_FIELD})
        url = self._url(f"_apis/wit/workitems/{id}", _API_VERSION)
        with _tracer.start_as_current_span("ado.update_work_item"):
            response = await self._request(
                "PATCH", url, json_body=patch, content_type=_JSON_PATCH_CONTENT_TYPE
            )
            return self._to_result(response.json(), action="updated")

    async def add_comment(self, id: int, text: str) -> None:
        """Add a comment to a work item — only on a material update (§5.2.5)."""
        url = self._url(f"_apis/wit/workItems/{id}/comments", _COMMENTS_API_VERSION)
        with _tracer.start_as_current_span("ado.add_comment"):
            await self._request("POST", url, json_body={"text": text})

    def _build_patch(self, fields: dict[str, Any]) -> list[dict[str, Any]]:
        """Build the JSON Patch document ADO requires from a field map (§4.4).

        Produces one ``add`` op per field targeting ``/fields/<reference-name>``;
        datetimes are serialized to ISO-8601 so the body is JSON-encodable.
        """
        return [
            {"op": "add", "path": f"/fields/{name}", "value": self._json_safe(value)}
            for name, value in fields.items()
        ]

    @staticmethod
    def _json_safe(value: Any) -> Any:
        """Coerce non-JSON-native values (datetimes) for the ADO body (§4.4)."""
        if isinstance(value, datetime | date):
            return value.isoformat()
        return value

    def _url(self, path: str, api_version: str) -> str:
        """Build an absolute ADO REST URL for the configured org/project (§6.1)."""
        return f"{self._org_url}/{self._project}/{path}?api-version={api_version}"

    def _to_result(
        self, data: dict[str, Any], *, action: Literal["created", "updated"]
    ) -> WorkItemResult:
        """Map an ADO work-item response into a :class:`WorkItemResult` (§4.4)."""
        links = data.get("_links", {})
        html = links.get("html", {}) if isinstance(links, dict) else {}
        url = html.get("href") or data.get("url", "")
        return WorkItemResult(id=int(data["id"]), url=str(url), action=action)

    @retry(
        reraise=True,
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=0.1, max=2.0),
        retry=retry_if_exception_type(_AdoRetryableError),
    )
    async def _request(
        self,
        method: str,
        url: str,
        *,
        json_body: Any = None,
        content_type: str = "application/json",
    ) -> httpx.Response:
        """Send one ADO request; retry 401/429/5xx/timeout via ``tenacity`` (§6.1)."""
        assert self._client is not None  # guarded by callers; narrows for mypy
        token = await self._get_token()
        headers = {"Authorization": f"Bearer {token}", "Content-Type": content_type}

        try:
            response = await self._client.request(method, url, json=json_body, headers=headers)
        except httpx.TimeoutException as exc:
            logger.warning("ADO request timed out: %s", exc)
            raise _AdoRetryableError(f"ADO request timed out: {exc}") from exc
        except httpx.HTTPError as exc:
            logger.warning("ADO transport error: %s", exc)
            raise _AdoRetryableError(f"ADO transport error: {exc}") from exc

        status = response.status_code
        if status == 401:
            # Invalidate the cached token so the retry re-acquires it (§6.1).
            logger.info("ADO returned 401; refreshing Managed Identity token")
            self._token = None
            self._token_expires_on = 0.0
            raise _AdoRetryableError("ADO returned 401 (token refreshed)")
        if status == 429 or status >= 500:
            logger.warning("ADO returned retryable status %d", status)
            raise _AdoRetryableError(f"ADO returned retryable status {status}")
        if status >= 400:
            raise AdoClientError(f"ADO returned status {status}: {response.text[:500]}")

        return response

    async def _get_token(self) -> str:
        """Return a cached ADO bearer token, refreshing near expiry (§6.1, §7)."""
        now = time.time()
        if self._token is not None and now < self._token_expires_on - _TOKEN_REFRESH_SKEW_SECONDS:
            return self._token
        try:
            access = await self._credential.get_token(self._scope)
        except Exception as exc:  # wrap any auth failure uniformly; never retried
            raise AdoClientError(f"failed to acquire ADO token: {exc}") from exc
        self._token = access.token
        self._token_expires_on = float(access.expires_on)
        return self._token
