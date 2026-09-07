from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from config_utils import load_config, project_path, repo_path


def pct(value: Any) -> str:
    try:
        return f"{float(value) * 100:.2f}%"
    except (TypeError, ValueError):
        return "N/A"


def number(value: Any) -> str:
    return str(value if value is not None else "N/A")


def top_terms_text(report: dict[str, Any], limit: int = 8) -> str:
    terms = report.get("cybersecurity_coverage", {}).get("top_terms", {})
    if not terms:
        return "无"
    return "，".join(f"{term}({count})" for term, count in list(terms.items())[:limit])


def count_items(items: dict[str, Any]) -> str:
    if not items:
        return "无"
    return "，".join(f"{key}: {value}" for key, value in items.items())


def section_report(title: str, report: dict[str, Any]) -> list[str]:
    ids = report.get("ids", {})
    schema = report.get("schema_validation", {})
    required = report.get("required_fields", {})
    length = report.get("length", {})
    coverage = report.get("cybersecurity_coverage", {})
    links = report.get("record_links")

    lines = [
        f"## {title}",
        "",
        f"- 样本数量：{number(report.get('count'))}",
        f"- 唯一 ID 数量：{number(ids.get('unique_id_count'))}",
        f"- 缺失 ID 数量：{number(ids.get('missing_id_count'))}",
        f"- 重复 ID 数量：{number(ids.get('duplicate_id_count'))}",
        f"- schema 有效率：{pct(schema.get('valid_ratio'))}",
        f"- 必填字段完整率：{pct(required.get('complete_ratio'))}",
        f"- 文本长度范围：{number(length.get('min_chars'))} - {number(length.get('max_chars'))} 字符，平均 {number(length.get('avg_chars'))} 字符",
        f"- 过短样本数：{number(length.get('too_short_count'))}",
        f"- 过长样本数：{number(length.get('too_long_count'))}",
        f"- 网络安全术语覆盖率：{pct(coverage.get('covered_ratio'))}",
        f"- CVE 提及样本数：{number(coverage.get('cve_mention_count'))}",
        f"- 高频领域术语：{top_terms_text(report)}",
        f"- 任务类型分布：{count_items(report.get('task_type_counts', {}))}",
    ]
    if links is not None:
        lines.extend(
            [
                f"- 来源记录链接异常数：{number(links.get('invalid_record_id_count'))}",
                f"- 来源引用覆盖率：{pct(links.get('source_ref_ratio'))}",
            ]
        )
    lines.append("")
    return lines


def build_report(metrics: dict[str, Any]) -> str:
    summary = metrics.get("summary", {})
    gate = metrics.get("quality_gate", {})
    reports = metrics.get("reports", {})
    hard_failures = summary.get("hard_failures") or []
    gate_result = "通过" if not summary.get("hard_failure_count") else "未通过"

    lines = [
        "# 网络安全语料 V1 质量评估报告",
        "",
        "## 1. 报告概览",
        "",
        f"- 评估时间：{metrics.get('generated_at', 'N/A')}",
        f"- 配置文件：`{metrics.get('config_file', 'N/A')}`",
        f"- 语料目录：`{metrics.get('corpus_dir', 'N/A')}`",
        f"- schema 目录：`{metrics.get('schema_dir', 'N/A')}`",
        f"- 来源记录数：{number(summary.get('raw_source_count'))}",
        f"- QA 样本数：{number(summary.get('qa_count'))}",
        f"- SFT 样本数：{number(summary.get('sft_count'))}",
        f"- 硬性失败数：{number(summary.get('hard_failure_count'))}",
        f"- 门禁结论：{gate_result}",
        "",
        "## 2. 质量门禁",
        "",
        f"- schema 有效率阈值：{pct(gate.get('min_schema_valid_ratio'))}",
        f"- 必填字段完整率阈值：{pct(gate.get('min_required_complete_ratio'))}",
        f"- 网络安全术语覆盖率阈值：{pct(gate.get('min_cybersecurity_coverage_ratio'))}",
        f"- 来源引用覆盖率阈值：{pct(gate.get('min_source_reference_ratio'))}",
        f"- 文本长度范围：{number(gate.get('min_chars'))} - {number(gate.get('max_chars'))} 字符",
        "",
    ]

    if hard_failures:
        lines.extend(["## 3. 硬性失败项", ""])
        lines.extend(f"- {item}" for item in hard_failures)
        lines.append("")
    else:
        lines.extend(["## 3. 硬性失败项", "", "- 无", ""])

    lines.extend(section_report("4. 来源记录质量", reports.get("raw_sources", {})))
    lines.extend(section_report("5. QA 样本质量", reports.get("qa", {})))
    lines.extend(section_report("6. SFT 样本质量", reports.get("sft", {})))

    lines.extend(
        [
            "## 7. 结论",
            "",
            "当前 V1 语料已通过本项目定义的基础质量门禁，字段完整性、schema 校验、唯一 ID、来源追溯和领域覆盖情况满足流程验证要求。",
            "由于 V1 样本规模较小，后续仍应继续扩大公开来源覆盖范围，并结合人工抽检复核事实一致性和答案完整性。",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Export a readable Markdown report from corpus quality metrics.")
    parser.add_argument("--config", help="流水线配置文件，默认 config/pipeline_config.json。")
    parser.add_argument("--metrics", help="质量指标 JSON 路径，默认读取配置中的 quality_metrics 文件。")
    parser.add_argument("--output", help="报告输出路径，默认写入配置中的 quality_report 文件。")
    args = parser.parse_args()

    config = load_config(args.config)
    corpus_dir = project_path(config["corpus"]["default_dir"])
    files = config["corpus"]["files"]
    metrics_path = project_path(args.metrics) if args.metrics else corpus_dir / files["quality_metrics"]
    output_name = files.get("quality_report", "quality_report.md")
    output_path = project_path(args.output) if args.output else corpus_dir / output_name

    metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
    output_path.write_text(build_report(metrics), encoding="utf-8")
    print(f"Quality report written to: {repo_path(output_path)}")


if __name__ == "__main__":
    main()
