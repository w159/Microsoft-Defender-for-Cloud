"""§4.5 — Durable activity: render the HTML Triage Briefing (pure, no I/O).

Renders the §4.5 template via Jinja2 from ``templates/triage_briefing.html.j2``.
Each section is guarded so partial enrichment renders cleanly (§5.2.3). Output is
HTML (the ADO ``Description`` field accepts HTML); values are auto-escaped.
"""

from __future__ import annotations

import html as _html
import logging
import re
import time
from functools import lru_cache
from pathlib import Path

import azure.durable_functions as df
from jinja2 import Environment, FileSystemLoader, Template, select_autoescape
from markupsafe import Markup, escape
from opentelemetry import trace

from models.briefing import BriefingInput

logger = logging.getLogger(__name__)
_tracer = trace.get_tracer(__name__)
bp = df.Blueprint()

_TEMPLATE_DIR = Path(__file__).parent / "templates"
_TEMPLATE_NAME = "triage_briefing.html.j2"

# MDC recommendation/remediation text arrives as small HTML fragments
# (<br>, </br>, <a href>, ...). These patterns reduce it to clean plain text (§4.5).
_DROP_RE = re.compile(r"(?is)<\s*(script|style)\b[^>]*>.*?<\s*/\s*\1\s*>")
_BREAK_RE = re.compile(r"(?i)<\s*/?\s*br\s*/?\s*>")
_BLOCK_RE = re.compile(r"(?i)<\s*/?\s*(p|div|li|ul|ol|tr|h[1-6]|table)\b[^>]*>")
_TAG_RE = re.compile(r"<[^>]+>")
# Sentinel marks an intentional (tag-driven) line break so it survives the
# whitespace collapse that flattens incidental word-wrap newlines in the source.
_BREAK_MARK = "\x00"


def strip_html(value: str | None) -> Markup:
    """Convert an MDC HTML fragment to clean, readable plain text (§4.5).

    MDC supplies recommendation and remediation text as small HTML fragments. This
    drops every source tag (and any ``script``/``style`` blocks), decodes HTML
    entities, and flattens incidental word-wrap whitespace, preserving only the
    line breaks expressed by ``<br>``/block tags as a single ``<br>``. The text
    content is escaped before those breaks are re-inserted, so no MDC-supplied
    markup can be injected into the Work Item.
    """
    if not value:
        return Markup("")
    text = _DROP_RE.sub(" ", value)
    text = _BREAK_RE.sub(_BREAK_MARK, text)
    text = _BLOCK_RE.sub(_BREAK_MARK, text)
    text = _TAG_RE.sub("", text)
    text = _html.unescape(text)
    # Flatten all incidental whitespace (incl. source newlines/tabs); the sentinel
    # survives because it is not a whitespace character.
    text = re.sub(r"\s+", " ", text)
    cleaned: list[str] = []
    for part in (p.strip() for p in text.split(_BREAK_MARK)):
        if not part and (not cleaned or not cleaned[-1]):
            continue
        cleaned.append(part)
    body = "\n".join(cleaned).strip()
    return Markup(str(escape(body)).replace("\n", "<br>\n"))


@lru_cache(maxsize=1)
def _template() -> Template:
    """Load and cache the briefing template (§4.5)."""
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "j2", "html.j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["strip_html"] = strip_html
    return env.get_template(_TEMPLATE_NAME)


def render_briefing(briefing_input: BriefingInput) -> str:
    """§4.5 — render the HTML briefing from a validated input (pure)."""
    return _template().render(
        payload=briefing_input.payload,
        enrichment=briefing_input.enrichment,
        owner=briefing_input.owner,
    )


@bp.activity_trigger(input_name="briefing_input")
async def activity_build_triage_briefing(briefing_input: BriefingInput) -> str:
    """§4.5 — compose the HTML triage briefing (pure, no external I/O)."""
    model = BriefingInput.model_validate(briefing_input)
    start = time.perf_counter()
    with _tracer.start_as_current_span("activity.build_triage_briefing") as span:
        span.set_attribute("assessment_id", model.payload.name or "")
        span.set_attribute("resource_id", model.payload.resource_id or "")
        html = render_briefing(model)
        span.set_attribute("duration_ms", (time.perf_counter() - start) * 1000.0)
        return html
