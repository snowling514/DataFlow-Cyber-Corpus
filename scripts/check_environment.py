from __future__ import annotations

import importlib
import importlib.metadata
import json
import os
import platform
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
REQUIRED_PACKAGES = [
    {"package": "open-dataflow", "module": "dataflow"},
    {"package": "pandas", "module": "pandas"},
    {"package": "requests", "module": "requests"},
    {"package": "simhash", "module": "simhash"},
]
OPTIONAL_ENV_VARS = ["DF_API_KEY", "DEEPSEEK_MODEL", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"]


def package_status(package: str, module: str) -> dict[str, Any]:
    status: dict[str, Any] = {
        "package": package,
        "module": module,
        "installed": False,
        "importable": False,
        "version": None,
        "error": None,
    }
    try:
        status["version"] = importlib.metadata.version(package)
        status["installed"] = True
    except importlib.metadata.PackageNotFoundError:
        status["error"] = "package_not_found"
    try:
        importlib.import_module(module)
        status["importable"] = True
    except Exception as exc:  # noqa: BLE001 - environment diagnostics should report the original import error
        status["error"] = f"import_failed: {exc}"
    return status


def env_status(name: str) -> dict[str, Any]:
    value = os.getenv(name)
    return {
        "name": name,
        "set": bool(value),
        "display": "<set>" if value else "<missing>",
    }


def main() -> None:
    packages = [package_status(item["package"], item["module"]) for item in REQUIRED_PACKAGES]
    missing = [item for item in packages if not item["installed"] or not item["importable"]]
    report = {
        "project_root": str(ROOT),
        "python": {
            "executable": sys.executable,
            "version": sys.version.split()[0],
            "platform": platform.platform(),
        },
        "packages": packages,
        "environment": [env_status(name) for name in OPTIONAL_ENV_VARS],
        "summary": {
            "required_package_count": len(REQUIRED_PACKAGES),
            "missing_or_broken_count": len(missing),
            "deepseek_ready": bool(os.getenv("DF_API_KEY")),
        },
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if missing:
        print("\nMissing or broken dependencies detected. Run: python -m pip install -r requirements.txt", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
