# PHP2Shell lab — convenience targets. Requires Docker + Docker Compose v2.
.PHONY: up down scan logs rebuild clean

up:            ## Build + start the three-version lab
	docker compose up --build -d
	@echo "EOL  -> http://localhost:8080   OUTDATED -> http://localhost:8081   PATCHED -> http://localhost:8082"

down:          ## Stop and remove containers
	docker compose down

rebuild:       ## Force a clean rebuild
	docker compose build --no-cache

scan:          ## Run the verdict scanner against the running lab
	bash scan/check.sh

logs:          ## Tail container logs
	docker compose logs -f

clean: down    ## Full teardown incl. built images
	docker compose down --rmi local -v
