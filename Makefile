up:
	docker compose up --build
test:
	pytest -q
lint:
	ruff check .
