.PHONY: help init validate audit trivy test all clean

SHELL := /bin/bash
TERRAFORM_DIR := terraform
SECURITY_DIR := security_suite
TESTS_DIR := tests

help:
	@echo "================================================================================"
	@echo "   SECURE AWS & KUBERNETES MULTI-STANDARD COMPLIANCE ENGINE (MAKEFILE)          "
	@echo "   Standards: NIST 800-53 R5 | ISO 27002:2022 | SOC 2 Type II | PCI DSS | FIPS  "
	@echo "================================================================================"
	@echo "Available commands:"
	@echo "  make init      - Initialize Terraform providers"
	@echo "  make validate  - Run Terraform syntax and semantic validation"
	@echo "  make audit     - Run Checkov 5-framework automated compliance audit"
	@echo "  make trivy     - Run Trivy CVE and secret vulnerability scan"
	@echo "  make test      - Run Python compliance assertion unit tests"
	@echo "  make all       - Run the complete validation and compliance audit suite"
	@echo "  make clean     - Clean temporary audit reports and cache files"

init:
	@echo "==> Initializing Terraform with AWS provider..."
	terraform -chdir=$(TERRAFORM_DIR) init

validate:
	@echo "==> Validating Terraform infrastructure code..."
	terraform -chdir=$(TERRAFORM_DIR) validate

audit:
	@echo "==> Executing Enterprise Multi-Standard Compliance Audit..."
	python3 $(SECURITY_DIR)/run_compliance_audit.py

trivy:
	@echo "==> Executing Trivy Vulnerability & Secret Audit..."
	bash $(SECURITY_DIR)/trivy_scan.sh

test:
	@echo "==> Running Compliance Guardrail Assertion Tests..."
	python3 -m unittest discover -s $(TESTS_DIR) -v

all: validate test audit trivy
	@echo ""
	@echo "================================================================================"
	@echo " [✓] ALL COMPLIANCE GATES VERIFIED: 100% PASS RATE"
	@echo "================================================================================"

clean:
	@rm -f *.json *.log
	@find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	@echo "==> Cleaned temporary artifacts."
