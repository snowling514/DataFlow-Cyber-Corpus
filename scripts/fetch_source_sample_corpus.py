from __future__ import annotations

import json
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Any

import requests

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "source_sample_corpus"
OUT.mkdir(parents=True, exist_ok=True)
CORPUS_JSONL = OUT / "sample_cyber_corpus_from_sources.jsonl"
SUMMARY_TXT = OUT / "source_sample_corpus_summary.txt"
METADATA_JSON = OUT / "fetch_metadata.json"

HEADERS = {"User-Agent": "DataFlow course project sample corpus builder/1.0"}

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API = "https://api.first.org/data/v1/epss"
CVELIST_RAW = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{year}/{bucket}/{cve}.json"
CICIDS2017_URL = "https://www.unb.ca/cic/datasets/ids-2017.html"
UNSW_NB15_URL = "https://research.unsw.edu.au/projects/unsw-nb15-dataset"


def get_json(url: str, params: dict[str, Any] | None = None) -> Any:
    attempts = 4 if "services.nvd.nist.gov" in url else 2
    last_exc = None
    for attempt in range(attempts):
        try:
            r = requests.get(url, params=params, headers=HEADERS, timeout=60)
            if r.status_code in (429, 500, 502, 503, 504) and attempt < attempts - 1:
                time.sleep(6 + attempt * 4)
                continue
            r.raise_for_status()
            return r.json()
        except Exception as exc:
            last_exc = exc
            if attempt < attempts - 1:
                time.sleep(6 + attempt * 4)
                continue
            raise last_exc


def get_text(url: str) -> str:
    r = requests.get(url, headers=HEADERS, timeout=60)
    r.raise_for_status()
    return r.text


def cvelist_url(cve_id: str) -> str:
    m = re.fullmatch(r"CVE-(\d{4})-(\d+)", cve_id)
    if not m:
        raise ValueError(cve_id)
    year, num_s = m.groups()
    num = int(num_s)
    bucket_start = (num // 1000) * 1000
    bucket = f"{bucket_start // 1000}xxx" if bucket_start else "0xxx"
    return CVELIST_RAW.format(year=year, bucket=bucket, cve=cve_id)


def extract_nvd(cve_id: str) -> dict[str, Any]:
    try:
        data = get_json(NVD_API, {"cveId": cve_id})
    except Exception as exc:
        return {"nvd_error": str(exc)[:300], "nvd_source_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"}
    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return {}
    cve = vulns[0].get("cve", {})
    desc = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            desc = d.get("value", "")
            break
    metrics = cve.get("metrics", {})
    severity = None
    base_score = None
    vector = None
    for key in ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if key in metrics and metrics[key]:
            metric = metrics[key][0]
            cvss = metric.get("cvssData", {})
            severity = metric.get("baseSeverity") or cvss.get("baseSeverity")
            base_score = cvss.get("baseScore")
            vector = cvss.get("vectorString")
            break
    weaknesses = []
    for weakness in cve.get("weaknesses", []):
        for d in weakness.get("description", []):
            if d.get("lang") == "en":
                weaknesses.append(d.get("value"))
    refs_obj = cve.get("references", [])
    if isinstance(refs_obj, dict):
        refs_iter = refs_obj.get("referenceData", [])
    else:
        refs_iter = refs_obj
    refs = [r.get("url") for r in refs_iter if isinstance(r, dict) and r.get("url")]
    return {
        "nvd_description": desc,
        "nvd_published": cve.get("published"),
        "nvd_last_modified": cve.get("lastModified"),
        "nvd_vuln_status": cve.get("vulnStatus"),
        "cvss_severity": severity,
        "cvss_base_score": base_score,
        "cvss_vector": vector,
        "cwe": sorted(set(x for x in weaknesses if x)),
        "references": refs[:8],
        "nvd_source_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
    }


def extract_epss(cve_ids: list[str]) -> dict[str, Any]:
    data = get_json(EPSS_API, {"cve": ",".join(cve_ids)})
    return {row["cve"]: row for row in data.get("data", [])}


def extract_cvelist(cve_id: str) -> dict[str, Any]:
    url = cvelist_url(cve_id)
    try:
        data = get_json(url)
    except Exception as exc:
        return {"cvelist_source_url": url, "cvelist_available": False, "cvelist_error": str(exc)[:200]}
    containers = data.get("containers", {})
    cna = containers.get("cna", {})
    descriptions = cna.get("descriptions", [])
    cna_desc = ""
    for d in descriptions:
        if d.get("lang") == "en":
            cna_desc = d.get("value", "")
            break
    affected = []
    for item in cna.get("affected", [])[:5]:
        vendor = item.get("vendor")
        product = item.get("product")
        if vendor or product:
            affected.append({"vendor": vendor, "product": product})
    return {
        "cvelist_source_url": url,
        "cvelist_available": True,
        "cna_title": cna.get("title"),
        "cna_description": cna_desc,
        "affected": affected,
    }


def clean_html_summary(html: str, keywords: list[str], fallback: str) -> str:
    text = re.sub(r"<script.*?</script>|<style.*?</style>", " ", html, flags=re.I | re.S)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text)
    lower = text.lower()
    pieces = []
    for kw in keywords:
        idx = lower.find(kw.lower())
        if idx >= 0:
            start = max(0, idx - 180)
            end = min(len(text), idx + 420)
            pieces.append(text[start:end].strip())
    return " ".join(pieces[:2]) or fallback


def build_cve_records() -> tuple[list[dict[str, Any]], dict[str, Any]]:
    kev = get_json(CISA_KEV_URL)
    vulns = kev.get("vulnerabilities", [])
    # Pick recent KEV items with complete fields. Sort descending by dateAdded.
    vulns = sorted(vulns, key=lambda x: x.get("dateAdded", ""), reverse=True)
    selected = [v for v in vulns if not v.get("cveID", "").startswith("CVE-2026-")][:8]
    cve_ids = [v["cveID"] for v in selected]
    epss = extract_epss(cve_ids)
    records = []
    for item in selected:
        cve_id = item["cveID"]
        nvd = extract_nvd(cve_id)
        cvelist = extract_cvelist(cve_id)
        epss_row = epss.get(cve_id, {})
        text_parts = [
            f"{cve_id}: {item.get('vendorProject', '')} {item.get('product', '')} known exploited vulnerability.",
            f"CISA vulnerability name: {item.get('vulnerabilityName', '')}.",
            f"CISA short description: {item.get('shortDescription', '')}",
        ]
        if nvd.get("nvd_description"):
            text_parts.append(f"NVD description: {nvd['nvd_description']}")
        if item.get("requiredAction"):
            text_parts.append(f"Required action: {item.get('requiredAction')}")
        if epss_row:
            text_parts.append(f"EPSS score: {epss_row.get('epss')} percentile: {epss_row.get('percentile')} date: {epss_row.get('date')}.")
        record = {
            "record_id": f"kev_nvd_epss_{cve_id}",
            "record_type": "vulnerability_text",
            "primary_source": "CISA KEV + NVD CVE API + FIRST EPSS",
            "cve_id": cve_id,
            "title": item.get("vulnerabilityName") or nvd.get("cna_title") or cve_id,
            "text": " ".join(x for x in text_parts if x),
            "source_urls": {
                "cisa_kev_feed": CISA_KEV_URL,
                "nvd_detail": nvd.get("nvd_source_url"),
                "epss_api": EPSS_API,
                "cvelist_v5": cvelist.get("cvelist_source_url"),
            },
            "cisa": item,
            "nvd": nvd,
            "epss": epss_row,
            "cvelist_v5": cvelist,
            "tags": ["cve", "known_exploited", "vulnerability", "kev"],
        }
        records.append(record)
    metadata = {
        "cisa_catalog_version": kev.get("catalogVersion"),
        "cisa_date_released": kev.get("dateReleased"),
        "cisa_count": kev.get("count"),
        "selected_cve_ids": cve_ids,
    }
    return records, metadata


def build_dataset_profile_records() -> list[dict[str, Any]]:
    cic_html = get_text(CICIDS2017_URL)
    unsw_html = get_text(UNSW_NB15_URL)
    cic_text = clean_html_summary(
        cic_html,
        ["The CICIDS2017 dataset", "attacks", "benign"],
        "CICIDS2017 is an intrusion detection dataset from the Canadian Institute for Cybersecurity containing benign and attack traffic for IDS evaluation.",
    )
    unsw_text = clean_html_summary(
        unsw_html,
        ["UNSW-NB15", "attack", "normal"],
        "UNSW-NB15 is a network intrusion dataset containing normal and attack records created for cybersecurity analytics research.",
    )
    return [
        {
            "record_id": "dataset_profile_cicids2017",
            "record_type": "dataset_profile",
            "primary_source": "Canadian Institute for Cybersecurity CICIDS2017 page",
            "title": "CICIDS2017 intrusion detection dataset profile",
            "text": "CICIDS2017 source summary: " + cic_text,
            "source_urls": {"official_page": CICIDS2017_URL},
            "tags": ["ids", "traffic", "dataset", "cicids2017"],
        },
        {
            "record_id": "dataset_profile_unsw_nb15",
            "record_type": "dataset_profile",
            "primary_source": "UNSW NB15 official dataset page",
            "title": "UNSW-NB15 intrusion dataset profile",
            "text": "UNSW-NB15 source summary: " + unsw_text,
            "source_urls": {"official_page": UNSW_NB15_URL},
            "tags": ["ids", "traffic", "dataset", "unsw-nb15"],
        },
    ]


def write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


def main() -> None:
    cve_records, metadata = build_cve_records()
    dataset_records = build_dataset_profile_records()
    records = cve_records + dataset_records
    write_jsonl(CORPUS_JSONL, records)
    now = datetime.now().isoformat(timespec="seconds")
    source_counts = {}
    for r in records:
        source_counts[r["record_type"]] = source_counts.get(r["record_type"], 0) + 1
    metadata.update({
        "generated_at": now,
        "record_count": len(records),
        "record_type_counts": source_counts,
        "output_jsonl": str(CORPUS_JSONL),
        "sources": {
            "nvd_api_docs": "https://nvd.nist.gov/developers/vulnerabilities",
            "nvd_api": NVD_API,
            "cisa_kev": CISA_KEV_URL,
            "epss_api_docs": "https://www.first.org/epss/api",
            "epss_api": EPSS_API,
            "cvelist_v5": "https://github.com/CVEProject/cvelistV5",
            "cicids2017": CICIDS2017_URL,
            "unsw_nb15": UNSW_NB15_URL,
        },
    })
    METADATA_JSON.write_text(json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8")

    lines = [
        "网络安全公开数据源样例语料汇总",
        "================================",
        "",
        f"生成时间：{now}",
        f"样例语料文件：{CORPUS_JSONL}",
        f"记录总数：{len(records)}",
        "",
        "一、数据源说明",
        "------------",
        "1. NVD CVE API：用于补全 CVE 描述、发布时间、CVSS 严重等级、CWE 和参考链接。",
        "2. CISA KEV：用于选择已知被利用漏洞，并提供漏洞名称、厂商、产品、处置要求和加入 KEV 日期。",
        "3. FIRST EPSS：用于补充 CVE 被利用概率分数和百分位。",
        "4. CVEProject cvelistV5：尝试补充 CVE 官方 JSON/CNA 描述和受影响产品。",
        "5. CICIDS2017 与 UNSW-NB15：作为网络流量/入侵检测数据集说明型语料加入，后续若要做流量分类，可再下载原始 CSV/PCAP。",
        "",
        "二、样例记录",
        "------------",
    ]
    for idx, r in enumerate(records, 1):
        lines.extend([
            f"{idx}. {r['record_id']}",
            f"   类型：{r['record_type']}",
            f"   标题：{r['title']}",
            f"   来源：{r['primary_source']}",
            f"   文本摘要：{r['text'][:500]}",
            "",
        ])
    lines.extend([
        "三、后续使用建议",
        "----------------",
        "这份文件可以作为网络安全语料处理实验的真实来源样例。下一步可以用 DataFlow 对 text 字段做清洗、长度过滤、去重和领域关键词评估，产出 cyber_corpus_v1.jsonl。",
        "",
    ])
    SUMMARY_TXT.write_text("\n".join(lines), encoding="utf-8")
    print(json.dumps(metadata, ensure_ascii=False, indent=2))
    print(f"Wrote {CORPUS_JSONL}")
    print(f"Wrote {SUMMARY_TXT}")


if __name__ == "__main__":
    main()





