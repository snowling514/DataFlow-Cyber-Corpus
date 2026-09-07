# 网络安全语料 V1 质量评估报告

## 1. 报告概览

- 评估时间：2026-09-07T11:45:25
- 配置文件：`config/pipeline_config.json`
- 语料目录：`cyber_training_corpus_v1`
- schema 目录：`schemas`
- 来源记录数：10
- QA 样本数：44
- SFT 样本数：26
- 硬性失败数：0
- 门禁结论：通过

## 2. 质量门禁

- schema 有效率阈值：100.00%
- 必填字段完整率阈值：100.00%
- 网络安全术语覆盖率阈值：80.00%
- 来源引用覆盖率阈值：80.00%
- 文本长度范围：20 - 4000 字符

## 3. 硬性失败项

- 无

## 4. 来源记录质量

- 样本数量：10
- 唯一 ID 数量：10
- 缺失 ID 数量：0
- 重复 ID 数量：0
- schema 有效率：100.00%
- 必填字段完整率：100.00%
- 文本长度范围：866 - 1656 字符，平均 1173.8 字符
- 过短样本数：0
- 过长样本数：0
- 网络安全术语覆盖率：100.00%
- CVE 提及样本数：8
- 高频领域术语：rce(10)，exploit(9)，cve(8)，epss(8)，vulnerability(8)，mitigation(8)，attack(8)，port(3)
- 任务类型分布：unknown: 10

## 5. QA 样本质量

- 样本数量：44
- 唯一 ID 数量：44
- 缺失 ID 数量：0
- 重复 ID 数量：0
- schema 有效率：100.00%
- 必填字段完整率：100.00%
- 文本长度范围：59 - 807 字符，平均 223.39 字符
- 过短样本数：0
- 过长样本数：0
- 网络安全术语覆盖率：95.45%
- CVE 提及样本数：40
- 高频领域术语：cve(40)，漏洞(16)，cvss(9)，vulnerability(8)，epss(8)，风险(8)，mitigation(8)，修复(8)
- 任务类型分布：vulnerability_summary: 8，affected_product: 8，risk_assessment: 8，mitigation: 8，weakness_extraction: 8，dataset_description: 2，dataset_use: 2
- 来源记录链接异常数：0
- 来源引用覆盖率：100.00%

## 6. SFT 样本质量

- 样本数量：26
- 唯一 ID 数量：26
- 缺失 ID 数量：0
- 重复 ID 数量：0
- schema 有效率：100.00%
- 必填字段完整率：100.00%
- 文本长度范围：1189 - 3401 字符，平均 1948.04 字符
- 过短样本数：0
- 过长样本数：0
- 网络安全术语覆盖率：100.00%
- CVE 提及样本数：24
- 高频领域术语：rce(26)，cve(24)，cwe(24)，cvss(24)，epss(24)，vulnerability(24)，ransomware(24)，mitigation(24)
- 任务类型分布：summarize_vulnerability: 8，recommend_mitigation: 8，extract_structured_fields: 8，dataset_to_training_plan: 2
- 来源记录链接异常数：0
- 来源引用覆盖率：100.00%

## 7. 结论

当前 V1 语料已通过本项目定义的基础质量门禁，字段完整性、schema 校验、唯一 ID、来源追溯和领域覆盖情况满足流程验证要求。
由于 V1 样本规模较小，后续仍应继续扩大公开来源覆盖范围，并结合人工抽检复核事实一致性和答案完整性。
