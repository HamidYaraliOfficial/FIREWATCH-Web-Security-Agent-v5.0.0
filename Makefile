PYTHON ?= python

.PHONY: run test lint demo
run:
	PYTHONPATH=backend $(PYTHON) -m uvicorn app.main:app --host 127.0.0.1 --port 8000

test:
	python -m pip install -r backend/requirements-dev.txt
	cd backend && PYTHONPATH=. $(PYTHON) -m pytest -q -rA

lint:
	$(PYTHON) -m compileall -q backend/app
	node --check frontend/static/app.js

# Local-only intentionally vulnerable target. Use only in an isolated lab.
demo:
	PYTHONPATH=. $(PYTHON) -m uvicorn demo_target.main:app --host 127.0.0.1 --port 8765
