# 可控基准与对照测试

## 目的

验证情报富化和风险评分是否比“仅按告警等级分流”更有效。

## 对照设计

- 基准组：只按原始告警等级判断高风险；
- 实验组：告警等级 + 资产重要性 + IOC 富化 + 情报判定 + MITRE 标签；
- 数据集：`data/benchmark_alerts.jsonl`，可控、脱敏、带真实标签；
- 指标：高危召回率、精确率、误报数量和自动处理耗时。

## 运行

```bash
PYTHONPATH=src python scripts/generate_benchmark.py
PYTHONPATH=src python scripts/run_benchmark.py
```

## 输出

- `outputs/benchmark.json`
- `outputs/benchmark.md`

## MTTI 口径

项目不能在没有真实分析师参与的情况下声称生产 MTTI。Mtti 使用显式假设值：

```text
manual_seconds_per_alert_assumption = 180
```

实验组使用“自动处理实测耗时 + 人工确认 60 秒”的保守估算。报告同时显示自动处理耗时、人工确认假设和 MTTI 估算，明确区分实测与假设。

## 生产化要求

正式 POC 需要客户提供：

- 真实告警样本；
- 已确认的正负样本标签；
- 分析师处理基线；
- 资产重要性和业务影响；
- 允许接入的情报源。


