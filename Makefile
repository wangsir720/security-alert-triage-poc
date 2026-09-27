.PHONY: run test

run:
	PYTHONPATH=src python -m alert_triage.cli

test:
	PYTHONPATH=src python -m unittest discover -s tests -v

