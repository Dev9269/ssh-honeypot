.PHONY: install run dev clean docker test

install:
	pip install -r requirements.txt

run:
	python main.py

dev:
	python main.py --dashboard

docker:
	docker-compose up --build

docker-down:
	docker-compose down

clean:
	rm -rf logs/*.log logs/*.json logs/*.db logs/*.pem __pycache__ honeypot/__pycache__

test:
	python -m pytest tests/ -v

lint:
	python -m flake8 honeypot/ main.py

shell:
	python main.py --no-shell

dashboard:
	python main.py --dashboard

config:
	python main.py --config honeypot.yaml

help:
	python main.py --help
