from __future__ import annotations

import json
import sys
from typing import Any, TextIO


def emit(payload: dict[str, Any], *, stream: TextIO | None = None) -> None:
    print(
        json.dumps(payload, sort_keys=True, separators=(",", ":")),
        file=stream or sys.stdout,
    )
