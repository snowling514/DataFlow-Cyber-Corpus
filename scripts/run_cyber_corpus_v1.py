from __future__ import annotations

import json
import math
import re
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

import pandas as pd
from simhash import Simhash

from dataflow.operators.general_text import (
    ContentNullFilter,
    HtmlUrlRemoverRefiner,
    RemoveExtraSpacesRefiner,
    SimHashDeduplicateFilter,
    UniqueWordsFilter,
    WordNumberFilter,
)
from dataflow.utils.storage import FileStorage

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "cyber_corpus_v1"
RAW_DIR = OUT_DIR / "raw"
PIPELINE_DIR = OUT_DIR / "pipeline_cache"
REPORT_DIR = OUT_DIR / "reports"
RAW_FILE = RAW_DIR / "cyber_raw.jsonl"
V1_FILE = OUT_DIR / "cyber_corpus_v1.jsonl"
EVAL_JSON = REPORT_DIR / "initial_evaluation.json"
REPORT_TXT = REPORT_DIR / "cyber_corpus_v1_experiment_report.txt"

CYBER_KEYWORDS = [
    "cve", "vulnerability", "exploit", "attack", "malware", "ransomware",
    "phishing", "xss", "sql injection", "remote code execution", "privilege",
    "authentication", "ssh", "firewall", "ioc", "indicator", "patch", "mitigation",
    "port", "payload", "incident", "threat", "log", "scan", "backdoor",
    "lateral movement", "credential", "bruteforce", "webshell", "risk", "severity",
]


def ensure_dirs() -> None:
    for path in [RAW_DIR, PIPELINE_DIR, REPORT_DIR]:
        path.mkdir(parents=True, exist_ok=True)


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def read_jsonl(path: Path) -> pd.DataFrame:
    return pd.read_json(path, lines=True)


def build_raw_corpus() -> None:
    rows = [
        {
            "id": "CVE-001",
            "source_type": "cve",
            "title": "CVE-2025-1001 web file upload vulnerability",
            "text": "<p>CVE-2025-1001 affects ExampleCMS 4.2. The upload endpoint allows unauthenticated users to upload executable webshell files. Attackers can achieve remote code execution. See https://example.org/advisory/1001 for patch guidance.</p>",
            "severity": "high",
            "tags": ["cve", "rce", "webshell"],
        },
        {
            "id": "CVE-002",
            "source_type": "cve",
            "title": "SQL injection in asset inventory module",
            "text": "CVE-2025-1044 describes SQL injection in the asset inventory search API. A crafted query parameter may disclose usernames, password hashes, and asset metadata. Mitigation: upgrade to 3.8.7 and enable prepared statements.",
            "severity": "critical",
            "tags": ["cve", "sql injection", "database"],
        },
        {
            "id": "CVE-003",
            "source_type": "cve",
            "title": "XSS in admin dashboard",
            "text": "The admin dashboard stores untrusted script content in notification templates. When an administrator opens the dashboard, the browser executes attacker-controlled JavaScript. The vendor fixed the stored XSS issue in version 2.9.1.",
            "severity": "medium",
            "tags": ["xss", "web"],
        },
        {
            "id": "LOG-001",
            "source_type": "attack_log",
            "title": "SSH brute force alert",
            "text": "Firewall logs show 428 failed SSH login attempts against port 22 from 185.199.109.23 within ten minutes. The same source attempted usernames root, admin, deploy, and test. Recommended response: block the IP and check authentication logs.",
            "severity": "medium",
            "tags": ["ssh", "bruteforce", "log"],
        },
        {
            "id": "LOG-002",
            "source_type": "attack_log",
            "title": "Repeated inbound SSH scan",
            "text": "Firewall logs show 426 failed ssh login attempts against port 22 from 185.199.109.23 in a ten minute window. The source tried root, admin, deploy, and test accounts. Block the address and review authentication logs.",
            "severity": "medium",
            "tags": ["ssh", "bruteforce", "log"],
        },
        {
            "id": "MAL-001",
            "source_type": "malware_report",
            "title": "Ransomware behavior summary",
            "text": "The ransomware sample creates a scheduled task for persistence, deletes shadow copies, encrypts documents with a new extension, and contacts a command-and-control endpoint over HTTPS. Indicators include suspicious mutex names and unusual file rename bursts.",
            "severity": "high",
            "tags": ["malware", "ransomware", "ioc"],
        },
        {
            "id": "PHISH-001",
            "source_type": "phishing_report",
            "title": "Credential phishing email",
            "text": "A phishing email impersonates the security team and asks users to verify their mailbox. The landing page collects corporate credentials and forwards victims to the legitimate portal. Recommended mitigation includes domain takedown and user awareness notification.",
            "severity": "medium",
            "tags": ["phishing", "credential"],
        },
        {
            "id": "IR-001",
            "source_type": "incident_note",
            "title": "Lateral movement investigation",
            "text": "Incident responders observed lateral movement from a compromised workstation to a file server using stolen domain credentials. Windows event logs showed remote service creation followed by archive staging. Containment isolated the workstation and rotated affected passwords.",
            "severity": "high",
            "tags": ["incident", "lateral movement", "credential"],
        },
        {
            "id": "PATCH-001",
            "source_type": "advisory",
            "title": "Patch advisory for VPN gateway",
            "text": "The VPN gateway update fixes an authentication bypass affecting the management interface. Administrators should restrict management access to trusted networks, apply firmware 9.1.12, and review logs for suspicious configuration changes.",
            "severity": "high",
            "tags": ["patch", "vpn", "authentication"],
        },
        {
            "id": "CVE-004",
            "source_type": "cve",
            "title": "Privilege escalation in endpoint agent",
            "text": "A local privilege escalation vulnerability in the endpoint security agent allows a low-privileged user to replace a service binary before restart. Exploitation requires local access. The vendor recommends enabling tamper protection and installing the hotfix.",
            "severity": "high",
            "tags": ["privilege escalation", "endpoint"],
        },
        {
            "id": "WEB-001",
            "source_type": "web_attack",
            "title": "Path traversal request pattern",
            "text": "Web access logs contain repeated requests for ../../../../etc/passwd and encoded traversal payloads. The application returned HTTP 403 after the WAF rule matched the pattern. Analysts should verify that no successful file disclosure occurred.",
            "severity": "medium",
            "tags": ["path traversal", "waf", "log"],
        },
        {
            "id": "DUP-001",
            "source_type": "cve",
            "title": "Duplicate SQL injection note",
            "text": "CVE-2025-1044 describes SQL injection in the asset inventory search API. A crafted query parameter may disclose usernames, password hashes, and asset metadata. Mitigation: upgrade to 3.8.7 and enable prepared statements.",
            "severity": "critical",
            "tags": ["duplicate", "sql injection"],
        },
        {
            "id": "NOISE-001",
            "source_type": "noise",
            "title": "Empty row",
            "text": "   ",
            "severity": "unknown",
            "tags": ["noise"],
        },
        {
            "id": "NOISE-002",
            "source_type": "noise",
            "title": "Non-security news",
            "text": "The cafeteria menu includes rice, noodles, soup, fruit, and tea. Students can choose lunch options during the afternoon break.",
            "severity": "unknown",
            "tags": ["noise"],
        },
        {
            "id": "NOISE-003",
            "source_type": "noise",
            "title": "Too short",
            "text": "patch now",
            "severity": "unknown",
            "tags": ["noise"],
        },
    ]
    write_jsonl(RAW_FILE, rows)


def count_words(text: Any) -> int:
    if not isinstance(text, str):
        return 0
    return len(text.split())


def keyword_hits(text: Any) -> int:
    if not isinstance(text, str):
        return 0
    lower = text.lower()
    return sum(1 for kw in CYBER_KEYWORDS if kw in lower)


def has_html_or_url(text: Any) -> bool:
    if not isinstance(text, str):
        return False
    return bool(re.search(r"https?://|<[^>]+>", text, flags=re.I))


def exact_duplicate_count(texts: list[str]) -> int:
    counts = Counter(t for t in texts if isinstance(t, str) and t.strip())
    return sum(count - 1 for count in counts.values() if count > 1)


def near_duplicate_pairs(texts: list[str], threshold: float = 0.90) -> int:
    sims = []
    clean = [t for t in texts if isinstance(t, str) and t.strip()]
    hashes = [Simhash(t) for t in clean]
    for i in range(len(hashes)):
        for j in range(i + 1, len(hashes)):
            max_hashbit = max(len(bin(hashes[i].value)), len(bin(hashes[j].value)))
            similarity = 1 - hashes[i].distance(hashes[j]) / max_hashbit
            if similarity >= threshold:
                sims.append((i, j))
    return len(sims)


def evaluate(df: pd.DataFrame, label: str) -> dict[str, Any]:
    texts = df["text"].fillna("").astype(str).tolist() if "text" in df.columns else []
    word_counts = [count_words(t) for t in texts]
    keyword_counts = [keyword_hits(t) for t in texts]
    non_empty = [bool(t.strip()) for t in texts]
    valid_length = [8 <= wc <= 160 for wc in word_counts]
    cyber_related = [kc >= 1 for kc in keyword_counts]
    return {
        "label": label,
        "record_count": int(len(df)),
        "empty_count": int(sum(not x for x in non_empty)),
        "empty_ratio": round(sum(not x for x in non_empty) / len(df), 4) if len(df) else 0,
        "avg_word_count": round(sum(word_counts) / len(word_counts), 2) if word_counts else 0,
        "min_word_count": int(min(word_counts)) if word_counts else 0,
        "max_word_count": int(max(word_counts)) if word_counts else 0,
        "valid_length_count": int(sum(valid_length)),
        "valid_length_ratio": round(sum(valid_length) / len(df), 4) if len(df) else 0,
        "html_or_url_count": int(sum(has_html_or_url(t) for t in texts)),
        "exact_duplicate_extra_count": int(exact_duplicate_count(texts)),
        "near_duplicate_pair_count": int(near_duplicate_pairs(texts)),
        "cyber_keyword_hit_count": int(sum(keyword_counts)),
        "cyber_related_count": int(sum(cyber_related)),
        "cyber_related_ratio": round(sum(cyber_related) / len(df), 4) if len(df) else 0,
    }


def run_dataflow_pipeline() -> Path:
    storage = FileStorage(
        first_entry_file_name=str(RAW_FILE),
        cache_path=str(PIPELINE_DIR),
        file_name_prefix="cyber_pipeline",
        cache_type="jsonl",
    )
    HtmlUrlRemoverRefiner().run(storage.step(), input_key="text")
    RemoveExtraSpacesRefiner().run(storage.step(), input_key="text")
    ContentNullFilter().run(storage.step(), input_key="text", output_key="non_empty_label")
    WordNumberFilter(min_words=8, max_words=160).run(storage.step(), input_key="text", output_key="word_count")
    UniqueWordsFilter(threshold=0.35).run(storage.step(), input_key="text", output_key="unique_word_label")
    SimHashDeduplicateFilter(bound=0.08).run(storage.step(), input_key="text", output_key="dedup_label")
    return PIPELINE_DIR / "cyber_pipeline_step6.jsonl"


def domain_filter_and_format(intermediate_file: Path) -> pd.DataFrame:
    df = read_jsonl(intermediate_file)
    df["cyber_keyword_hits"] = df["text"].apply(keyword_hits)
    df["word_count_final"] = df["text"].apply(count_words)
    df = df[df["cyber_keyword_hits"] >= 1].copy()
    df["corpus_version"] = "V1"
    df["processing_notes"] = "html_url_removed; spaces_normalized; non_empty; length_filtered; diversity_filtered; simhash_deduplicated; domain_keyword_filtered"
    keep_cols = [
        "corpus_version", "id", "source_type", "title", "text", "severity", "tags",
        "word_count_final", "cyber_keyword_hits", "processing_notes",
    ]
    df = df[keep_cols].reset_index(drop=True)
    write_jsonl(V1_FILE, df.to_dict(orient="records"))
    return df


def write_reports(raw_eval: dict[str, Any], v1_eval: dict[str, Any], v1_df: pd.DataFrame) -> None:
    evaluation = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "pipeline": [
            "HtmlUrlRemoverRefiner(text)",
            "RemoveExtraSpacesRefiner(text)",
            "ContentNullFilter(text)",
            "WordNumberFilter(text, min_words=8, max_words=160)",
            "UniqueWordsFilter(text, threshold=0.35)",
            "SimHashDeduplicateFilter(text, bound=0.08)",
            "Custom domain keyword filter(keyword_hits >= 1)",
        ],
        "raw": raw_eval,
        "v1": v1_eval,
        "retention_ratio": round(v1_eval["record_count"] / raw_eval["record_count"], 4) if raw_eval["record_count"] else 0,
        "output_file": str(V1_FILE),
    }
    EVAL_JSON.write_text(json.dumps(evaluation, ensure_ascii=False, indent=2), encoding="utf-8")

    lines = [
        "网络安全语料处理实验、流水线优化与语料库 V1 初步评估报告",
        "========================================================",
        "",
        "一、实验目标",
        "------------",
        "本实验面向“大语言模型智能语料优化”项目的网络安全语料处理阶段，目标是使用 DataFlow 搭建一条可复现的网络安全语料处理流水线，完成原始样例语料清洗、质量过滤、近似去重、领域相关性筛选，并产出语料库 V1 与初步评估结果。",
        "",
        "二、输入数据",
        "------------",
        f"原始语料文件：{RAW_FILE}",
        f"原始样本数：{raw_eval['record_count']}",
        "样本类型覆盖：CVE 文本、漏洞公告、攻击日志、恶意软件报告、钓鱼报告、事件响应记录、补丁公告和少量噪声样本。",
        "",
        "三、流水线设计与优化思路",
        "------------------------",
        "1. HtmlUrlRemoverRefiner：删除 HTML 标签和 URL，减少网页采集噪声。",
        "2. RemoveExtraSpacesRefiner：规范空格，统一文本格式。",
        "3. ContentNullFilter：过滤空字符串和纯空白文本。",
        "4. WordNumberFilter：保留词数在 8 到 160 之间的样本，去除过短或异常过长文本。",
        "5. UniqueWordsFilter：过滤重复词比例过高、信息密度较低的样本。",
        "6. SimHashDeduplicateFilter：执行近似去重，减少重复或高度相似语料。",
        "7. 领域关键词筛选：保留至少命中 1 个网络安全关键词的样本，保证语料与网络安全主题相关。",
        "",
        "本次优化没有使用删除数字或删除标点的算子，因为 CVE 编号、端口号、版本号、路径、URL 片段等在网络安全语料中通常具有关键语义，过度清洗会损伤领域信息。",
        "",
        "四、语料库 V1 产出",
        "----------------",
        f"V1 输出文件：{V1_FILE}",
        f"V1 样本数：{v1_eval['record_count']}",
        f"保留率：{round(v1_eval['record_count'] / raw_eval['record_count'] * 100, 2)}%",
        "V1 字段包括：corpus_version、id、source_type、title、text、severity、tags、word_count_final、cyber_keyword_hits、processing_notes。",
        "",
        "五、初步评估结果",
        "----------------",
        f"1. 空内容数量：原始 {raw_eval['empty_count']} -> V1 {v1_eval['empty_count']}",
        f"2. HTML/URL 噪声数量：原始 {raw_eval['html_or_url_count']} -> V1 {v1_eval['html_or_url_count']}",
        f"3. 精确重复额外样本数：原始 {raw_eval['exact_duplicate_extra_count']} -> V1 {v1_eval['exact_duplicate_extra_count']}",
        f"4. 近似重复文本对数：原始 {raw_eval['near_duplicate_pair_count']} -> V1 {v1_eval['near_duplicate_pair_count']}",
        f"5. 合理长度样本比例：原始 {raw_eval['valid_length_ratio']} -> V1 {v1_eval['valid_length_ratio']}",
        f"6. 网络安全相关样本比例：原始 {raw_eval['cyber_related_ratio']} -> V1 {v1_eval['cyber_related_ratio']}",
        f"7. 平均词数：原始 {raw_eval['avg_word_count']} -> V1 {v1_eval['avg_word_count']}",
        "",
        "六、V1 样本清单",
        "--------------",
    ]
    for _, row in v1_df.iterrows():
        lines.append(f"- {row['id']} | {row['source_type']} | {row['title']} | words={row['word_count_final']} | keyword_hits={row['cyber_keyword_hits']}")
    lines.extend([
        "",
        "七、实验结论",
        "------------",
        "1. 本次实验成功构建了一条面向网络安全语料的 DataFlow 处理流水线。",
        "2. V1 语料库去除了空内容、明显噪声、低质量短文本和重复样本。",
        "3. 初步评估显示，V1 的网络安全相关性、长度合理性和去重质量均优于原始语料。",
        "4. 针对网络安全领域，流水线应保留数字、符号、CVE 编号、端口号和版本号等关键信息，避免套用过度通用化的清洗策略。",
        "5. 后续可引入更大规模 CVE 数据、NVD 公告、安全日志和漏洞报告，并增加人工抽检或模型打分评估，形成 V2。",
        "",
        "八、后续优化方向",
        "----------------",
        "1. 增加漏洞类型、攻击阶段、资产类型等标签字段。",
        "2. 使用 DeepSeek 或其他模型生成问答对、摘要和解释数据。",
        "3. 加入人工抽样检查，统计术语保真度和事实准确率。",
        "4. 建立 train/dev/test 划分，为小模型微调实验做准备。",
        "5. 在 V2 阶段引入真实 CVE/NVD 数据或课程指定数据集。",
        "",
    ])
    REPORT_TXT.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    ensure_dirs()
    build_raw_corpus()
    raw_df = read_jsonl(RAW_FILE)
    raw_eval = evaluate(raw_df, "raw")
    intermediate = run_dataflow_pipeline()
    v1_df = domain_filter_and_format(intermediate)
    v1_eval = evaluate(v1_df, "v1")
    write_reports(raw_eval, v1_eval, v1_df)
    print("Cybersecurity corpus V1 pipeline completed.")
    print(f"Raw corpus: {RAW_FILE}")
    print(f"V1 corpus: {V1_FILE}")
    print(f"Evaluation JSON: {EVAL_JSON}")
    print(f"Report TXT: {REPORT_TXT}")
    print(json.dumps({"raw": raw_eval, "v1": v1_eval}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
