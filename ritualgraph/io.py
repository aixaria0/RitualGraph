from __future__ import annotations

import json
from pathlib import Path

from .schema import ThreatModel


def load_model(path: str | Path) -> ThreatModel:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return ThreatModel.model_validate(data)
