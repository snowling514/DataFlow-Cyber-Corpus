from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = ROOT / "config" / "pipeline_config.json"


def project_path(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else ROOT / path


def repo_path(path: str | Path) -> str:
    resolved = project_path(path).resolve()
    try:
        return resolved.relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return str(resolved)


def load_config(path: str | Path | None = None) -> dict[str, Any]:
    config_path = project_path(path or DEFAULT_CONFIG)
    with config_path.open("r", encoding="utf-8") as f:
        config = json.load(f)
    config["_config_path"] = config_path
    return config
