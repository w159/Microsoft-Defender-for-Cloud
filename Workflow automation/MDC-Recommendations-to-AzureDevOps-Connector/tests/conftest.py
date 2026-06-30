"""Pytest configuration — make ``src/function`` importable as top-level packages.

Mirrors the Azure Functions runtime, where the app root (``src/function``) is on the
path so modules import as ``models.*`` / ``clients.*`` / ``activities.*``.
"""

from __future__ import annotations

import sys
from pathlib import Path

_FUNCTION_ROOT = Path(__file__).parent.parent / "src" / "function"
if str(_FUNCTION_ROOT) not in sys.path:
    sys.path.insert(0, str(_FUNCTION_ROOT))
