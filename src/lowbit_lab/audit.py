from __future__ import annotations

import hashlib
import uuid
from pathlib import Path

from lowbit_lab.db import ResultsDatabase


def begin_attempt(database: ResultsDatabase, config_path: Path, root: Path, started_at: str) -> str:
    try:
        with config_path.open("rb") as handle:
            raw_sha256 = hashlib.file_digest(handle, "sha256").hexdigest()
    except OSError:
        raw_sha256 = None
    attempt_id = str(uuid.uuid4())
    database.create_attempt(
        attempt_id=attempt_id,
        config_path=config_path.relative_to(root.resolve()).as_posix(),
        raw_config_sha256=raw_sha256,
        started_at=started_at,
    )
    return attempt_id


def failure_reason(exc: Exception) -> str:
    return f"{type(exc).__name__}: {exc}"[:2000]
