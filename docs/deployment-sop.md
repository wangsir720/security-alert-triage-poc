# 部署 SOP

## 环境要求

- Python 3.10+
- Docker 和 Docker Compose
- 可写目录 `outputs/`

## 本地运行

```bash
PYTHONPATH=src python -m alert_triage.cli
PYTHONPATH=src python -m alert_triage.web --port 8080
```

## Docker 运行

```bash
docker compose up --build
```

## 验收

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

检查输出：

- `outputs/latest.json`
- `outputs/latest.md`
- `outputs/latest.html`

## 演示前检查

- 样例数据不包含真实客户、人员或内部资产信息；
- 8 条告警全部进入报告；
- 至少有一条恶意 IOC 命中；
- Dashboard 页面可以正常访问；
- 报告中的风险分与处置建议能够解释。

