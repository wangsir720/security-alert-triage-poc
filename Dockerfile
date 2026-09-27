FROM python:3.12-slim

WORKDIR /app
COPY . /app

ENV PYTHONPATH=/app/src

CMD ["sh", "-c", "python -m alert_triage.cli --alerts data/sample_alerts.jsonl --intel data/threat_intel.json --output-dir outputs && python -m alert_triage.web --host 0.0.0.0 --port 8080 --output-dir outputs"]

