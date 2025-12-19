.PHONY: help install dev test lint format clean build run

# Colors
CYAN := \033[36m
GREEN := \033[32m
YELLOW := \033[33m
RESET := \033[0m

help: ## Show this help message
	@echo ""
	@echo "$(CYAN)Cloud Attack Surface Framework$(RESET)"
	@echo "$(GREEN)================================$(RESET)"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(CYAN)%-15s$(RESET) %s\n", $$1, $$2}'
	@echo ""

install: ## Install dependencies
	@echo "$(GREEN)Installing Python dependencies...$(RESET)"
	python3 -m venv .venv
	.venv/bin/pip install --upgrade pip
	.venv/bin/pip install -r requirements.txt
	@echo "$(GREEN)Building Go binaries...$(RESET)"
	cd src/go/skyscan && go build -o ../../../bin/skyscan_v2 ./cmd/skyscan/main.go
	@echo "$(GREEN)Installation complete!$(RESET)"

dev: ## Install development dependencies
	.venv/bin/pip install -e ".[dev]"

test: ## Run tests
	.venv/bin/pytest tests/ -v

lint: ## Run linters
	.venv/bin/ruff check src/python/
	.venv/bin/mypy src/python/orchestrator/

format: ## Format code
	.venv/bin/black src/python/
	.venv/bin/ruff check --fix src/python/

clean: ## Clean build artifacts
	rm -rf build/ dist/ *.egg-info/
	rm -rf .pytest_cache/ .mypy_cache/ .ruff_cache/
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	@echo "$(GREEN)Cleaned!$(RESET)"

build: ## Build Go binaries
	@echo "$(GREEN)Building SkyScan v2...$(RESET)"
	cd src/go/skyscan && go build -o ../../../bin/skyscan_v2 ./cmd/skyscan/main.go
	@echo "$(GREEN)Build complete!$(RESET)"

run: ## Run the CLI (use: make run ARGS="scan target")
	./cloud-asf $(ARGS)

scan: ## Quick scan (use: make scan TARGET=company)
	./cloud-asf scan $(TARGET) --mode fast

recon: ## Full recon (use: make recon TARGET=domain.com)
	./cloud-asf recon full $(TARGET)

storage: ## Storage enumeration (use: make storage TARGET=company)
	./cloud-asf storage enum $(TARGET)

secrets: ## Secret scanning (use: make secrets TARGET=./path)
	./cloud-asf secrets scan $(TARGET)

check: ## Check installed tools
	./cloud-asf check-tools

docker-build: ## Build Docker image
	docker build -t cloud-asf:latest .

docker-run: ## Run in Docker
	docker run -it --rm cloud-asf:latest $(ARGS)

update-tools: ## Update external tools
	@echo "$(YELLOW)Updating external tools...$(RESET)"
	./scripts/install_tools.sh
	@echo "$(GREEN)Tools updated!$(RESET)"
