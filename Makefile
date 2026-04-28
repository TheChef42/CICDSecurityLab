.PHONY: scan dashboard all clean

scan:
	docker compose run --rm scanner

dashboard:
	docker compose run --rm results-init
	docker compose up --build --no-deps web

all:
	docker compose up --build

clean:
	rm -rf results/raw results/normalized results/summary.json results/diagnostics.json
	mkdir -p results/raw results/normalized
	docker compose run --rm results-init node scanner/init-results.js --force
