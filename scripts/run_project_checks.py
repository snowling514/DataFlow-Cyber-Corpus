from __future__ import annotations

import json
import py_compile
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = ROOT / "scripts"
CONFIG_FILE = ROOT / "config" / "pipeline_config.json"
SENSITIVE_REGEXES = [
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
]
OUTDATED_SCOPE_PATTERNS = [
    "小" + "模型",
    "微调" + "实验",
    "指令" + "微调",
    "其他" + "模型",
]
TEXT_EXTENSIONS = {".md", ".py", ".json", ".jsonl", ".ps1"}
TEXT_FILE_ALLOWLIST = {"requirements.txt"}
SKIP_DIRS = {".git", ".venv", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", "results"}

sys.path.insert(0, str(SCRIPTS_DIR))

from check_environment import REQUIRED_PACKAGES, package_status  # noqa: E402
from config_utils import load_config, project_path, repo_path  # noqa: E402
from evaluate_training_corpus import build_metrics  # noqa: E402
from export_quality_report import build_report  # noqa: E402
from generate_corpus_manifest import build_manifest  # noqa: E402


def print_step(name: str) -> None:
    print(f"\n== {name} ==")


def check_json_file(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        json.load(f)
    return {"path": repo_path(path), "status": "ok"}


def iter_project_text_files() -> list[Path]:
    try:
        result = subprocess.run(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=True,
        )
        candidates = [ROOT / line.strip() for line in result.stdout.splitlines() if line.strip()]
    except Exception as exc:  # noqa: BLE001 - fallback keeps local verification usable outside git
        print(f"git file listing unavailable, using fallback scan: {exc}")
        candidates = [path for path in ROOT.rglob("*") if path.is_file()]

    files: list[Path] = []
    for path in candidates:
        if not path.exists() or not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.relative_to(ROOT).parts):
            continue
        if path.suffix.lower() in TEXT_EXTENSIONS or path.name in TEXT_FILE_ALLOWLIST:
            files.append(path)
    return sorted(files)


def scan_forbidden_patterns(patterns: list[str]) -> list[dict[str, Any]]:
    findings = []
    for path in iter_project_text_files():
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except UnicodeDecodeError:
            continue
        for line_no, line in enumerate(lines, 1):
            for pattern in patterns:
                if pattern in line:
                    findings.append({"file": repo_path(path), "line": line_no, "pattern": pattern})
    return findings


def scan_sensitive_patterns() -> list[dict[str, Any]]:
    findings = []
    for path in iter_project_text_files():
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except UnicodeDecodeError:
            continue
        for line_no, line in enumerate(lines, 1):
            for pattern in SENSITIVE_REGEXES:
                for match in pattern.finditer(line):
                    findings.append({"file": repo_path(path), "line": line_no, "pattern": pattern.pattern, "match_prefix": match.group(0)[:6]})
    return findings


def compile_scripts() -> list[dict[str, Any]]:
    compiled = []
    for path in sorted(SCRIPTS_DIR.glob("*.py")):
        py_compile.compile(str(path), doraise=True)
        compiled.append({"path": repo_path(path), "status": "ok"})
    return compiled


def check_required_files(config: dict[str, Any]) -> list[dict[str, Any]]:
    checks = []
    corpus_dir = project_path(config["corpus"]["default_dir"])
    source_file = project_path(config["corpus"]["source_file"])
    checks.append({"path": repo_path(source_file), "exists": source_file.exists()})
    for file_name in config["corpus"]["files"].values():
        path = corpus_dir / file_name
        checks.append({"path": repo_path(path), "exists": path.exists()})
    schema_dir = project_path(config["schemas"]["dir"])
    for file_name in config["schemas"]["files"].values():
        path = schema_dir / file_name
        checks.append({"path": repo_path(path), "exists": path.exists()})
    missing = [item["path"] for item in checks if not item["exists"]]
    if missing:
        raise RuntimeError(f"Required files missing: {missing}")
    return checks


def comparable_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    return {
        "manifest_version": manifest.get("manifest_version"),
        "config_file": manifest.get("config_file"),
        "project_root_name": manifest.get("project_root_name"),
        "file_count": manifest.get("file_count"),
        "missing_count": manifest.get("missing_count"),
        "missing_files": manifest.get("missing_files"),
        "files": sorted(manifest.get("files", []), key=lambda item: item.get("path", "")),
    }


def check_manifest(config: dict[str, Any]) -> dict[str, Any]:
    corpus_dir = project_path(config["corpus"]["default_dir"])
    manifest_path = corpus_dir / config["corpus"]["files"].get("manifest", "corpus_manifest.json")
    stored = json.loads(manifest_path.read_text(encoding="utf-8"))
    current = build_manifest(config)
    matches = comparable_manifest(stored) == comparable_manifest(current)
    if not matches:
        raise RuntimeError("Corpus manifest is stale. Run: python scripts/generate_corpus_manifest.py")
    return {"path": repo_path(manifest_path), "status": "ok", "file_count": stored.get("file_count")}


def check_quality_report(config: dict[str, Any]) -> dict[str, Any]:
    corpus_dir = project_path(config["corpus"]["default_dir"])
    files = config["corpus"]["files"]
    metrics_path = corpus_dir / files["quality_metrics"]
    report_path = corpus_dir / files.get("quality_report", "quality_report.md")
    stored = report_path.read_text(encoding="utf-8")
    metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
    expected = build_report(metrics)
    if stored != expected:
        raise RuntimeError("Quality report is stale. Run: python scripts/export_quality_report.py")
    return {"path": repo_path(report_path), "status": "ok"}


def main() -> None:
    print("Project checks for DataFlow cybersecurity corpus")

    print_step("Python Packages")
    package_results = [package_status(item["package"], item["module"]) for item in REQUIRED_PACKAGES]
    for item in package_results:
        print(f"{item['package']}: installed={item['installed']} importable={item['importable']} version={item['version']}")
    broken = [item for item in package_results if not item["installed"] or not item["importable"]]
    if broken:
        raise RuntimeError("Missing or broken Python dependencies. Run: python -m pip install -r requirements.txt")

    print_step("JSON Config And Schemas")
    config = load_config(CONFIG_FILE)
    json_checks = [check_json_file(CONFIG_FILE)]
    for file_name in config["schemas"]["files"].values():
        json_checks.append(check_json_file(project_path(config["schemas"]["dir"]) / file_name))
    for item in json_checks:
        print(f"{item['path']}: {item['status']}")

    print_step("Required Files")
    for item in check_required_files(config):
        print(f"{item['path']}: exists={item['exists']}")

    print_step("Python Compile")
    for item in compile_scripts():
        print(f"{item['path']}: {item['status']}")

    print_step("Corpus Quality Gate")
    metrics = build_metrics(project_path(config["corpus"]["default_dir"]), config)
    print(json.dumps(metrics["summary"], ensure_ascii=False, indent=2))
    if metrics["summary"]["hard_failure_count"]:
        raise RuntimeError("Corpus quality gate failed.")

    print_step("Quality Report")
    quality_report_result = check_quality_report(config)
    print(f"{quality_report_result['path']}: {quality_report_result['status']}")

    print_step("Corpus Manifest")
    manifest_result = check_manifest(config)
    print(f"{manifest_result['path']}: {manifest_result['status']} file_count={manifest_result['file_count']}")

    print_step("Sensitive And Scope Scan")
    sensitive_findings = scan_sensitive_patterns()
    scope_findings = scan_forbidden_patterns(OUTDATED_SCOPE_PATTERNS)
    print(f"sensitive_findings={len(sensitive_findings)}")
    print(f"outdated_scope_findings={len(scope_findings)}")
    if sensitive_findings:
        raise RuntimeError(f"Sensitive value found: {sensitive_findings}")
    if scope_findings:
        raise RuntimeError(f"Outdated project scope wording found: {scope_findings}")

    print("\nAll project checks passed.")


if __name__ == "__main__":
    main()
