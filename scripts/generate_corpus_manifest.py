from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from config_utils import load_config, project_path, repo_path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SCRIPT_FILES = [
    "scripts/fetch_source_sample_corpus.py",
    "scripts/build_training_corpus_v1.py",
    "scripts/process_new_content.py",
    "scripts/evaluate_training_corpus.py",
    "scripts/run_project_checks.py",
    "scripts/generate_corpus_manifest.py",
    "scripts/config_utils.py",
    "scripts/deepseek_utils.py",
]
SUPPORT_FILES = [
    "README.md",
    "requirements.txt",
]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def count_lines(path: Path) -> int | None:
    try:
        return len(path.read_text(encoding="utf-8").splitlines())
    except UnicodeDecodeError:
        return None


def file_record(path: Path, role: str) -> dict[str, Any]:
    return {
        "path": repo_path(path),
        "role": role,
        "exists": path.exists(),
        "bytes": path.stat().st_size if path.exists() else None,
        "line_count": count_lines(path) if path.exists() else None,
        "sha256": sha256_file(path) if path.exists() else None,
    }


def append_existing(records: list[dict[str, Any]], paths: list[Path], role: str) -> None:
    for path in paths:
        records.append(file_record(path, role))


def build_manifest(config: dict[str, Any]) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    corpus_dir = project_path(config["corpus"]["default_dir"])
    corpus_files = config["corpus"]["files"]
    schema_dir = project_path(config["schemas"]["dir"])

    append_existing(records, [project_path(config["_config_path"])], "config")
    append_existing(records, [project_path(config["corpus"]["source_file"])], "source_sample")
    append_existing(records, [corpus_dir / corpus_files["raw_sources"], corpus_dir / corpus_files["qa"], corpus_dir / corpus_files["sft"]], "corpus_v1")
    append_existing(records, [corpus_dir / corpus_files["quality_metrics"], corpus_dir / "build_metadata.json"], "metrics")
    append_existing(records, [schema_dir / name for name in config["schemas"]["files"].values()], "schema")
    append_existing(records, [project_path(path) for path in DEFAULT_SCRIPT_FILES], "script")
    append_existing(records, [project_path(path) for path in SUPPORT_FILES], "support")

    missing = [record["path"] for record in records if not record["exists"]]
    return {
        "manifest_version": "1.0",
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "config_file": repo_path(config["_config_path"]),
        "project_root_name": ROOT.name,
        "file_count": len(records),
        "missing_count": len(missing),
        "missing_files": missing,
        "files": records,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a reproducibility manifest for the cybersecurity corpus project.")
    parser.add_argument("--config", help="流水线配置文件，默认 config/pipeline_config.json。")
    parser.add_argument("--output", help="manifest 输出路径，默认写入配置中的 corpus.files.manifest。")
    args = parser.parse_args()

    config = load_config(args.config)
    manifest_file = config["corpus"]["files"].get("manifest", "corpus_manifest.json")
    corpus_dir = project_path(config["corpus"]["default_dir"])
    output_path = project_path(args.output) if args.output else corpus_dir / manifest_file
    manifest = build_manifest(config)
    output_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"file_count": manifest["file_count"], "missing_count": manifest["missing_count"], "output": repo_path(output_path)}, ensure_ascii=False, indent=2))
    if manifest["missing_count"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()

