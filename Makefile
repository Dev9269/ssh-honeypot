.PHONY: install run dev clean docker test

install:
	pip install -r requirements.txt

install-dev:
	pip install -r requirements.txt flake8 pytest

run:
	python main.py

run-dashboard:
	python main.py --dashboard

run-ai:
	python main.py --dashboard --ai

docker:
	docker-compose up --build

docker-down:
	docker-compose down

docker-logs:
	docker-compose logs -f

clean:
	rm -rf logs/*.log logs/*.json logs/*.db logs/*.pem __pycache__ honeypot/__pycache__

clean-logs:
	rm -rf logs/*.log logs/*.json logs/*.db

test:
	python -m pytest tests/ -v

test-coverage:
	python -m pytest tests/ -v --cov=honeypot

lint:
	python -m flake8 honeypot/ main.py

typecheck:
	python -m mypy honeypot/ --ignore-missing-imports || echo "mypy not installed, skipping"

shell:
	python main.py --no-shell

dashboard:
	python main.py --dashboard

config:
	python main.py --config honeypot.yaml

help:
	python main.py --help

.PHONY: install install-dev run run-dashboard run-ai docker docker-down docker-logs clean clean-logs test test-coverage lint typecheck shell dashboard config help
