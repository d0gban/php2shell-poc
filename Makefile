# PHP2Shell lab — convenience targets. Requires Docker + Docker Compose v2.
.PHONY: up down scan logs rebuild clean check behavior wafprobe rawlogs killchain

up:            ## Build + start the three-version lab
	docker compose up --build -d
	@echo "EOL  -> http://localhost:8080   OUTDATED -> http://localhost:8081   PATCHED -> http://localhost:8082"

down:          ## Stop and remove containers
	docker compose down

rebuild:       ## Force a clean rebuild
	docker compose build --no-cache

scan:          ## Run the verdict scanner against the running lab
	bash scan/check.sh

check:         ## Benign client-side PHP2Shell version checker (per-version verdicts)
	python3 scan/vuln-checker.py

behavior:      ## Per-version observable HTTP behaviour profile
	bash scan/behavior.sh

wafprobe:      ## Send benign attack-shaped probes (WAF/IDS detection tuning)
	bash scan/waf-test.sh

rawlogs:       ## Tail the per-version raw HTTP capture (mod_dumpio) on the host
	tail -n +1 -f logs/eol/error.log logs/outdated/error.log logs/patched/error.log

killchain:     ## Validate WAF blocks at each stage: passive/active recon + exploitation shape
	bash scan/killchain.sh

logs:          ## Tail container logs
	docker compose logs -f

clean: down    ## Full teardown incl. built images
	docker compose down --rmi local -v
