#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${ROOT_DIR}"

echo "Validating Terraform configurations..."
terraform -chdir=terraform validate

echo "Running compliance guardrail assertions..."
python3 -m unittest discover -s tests -v

echo "Running Checkov compliance audit..."
python3 security_suite/run_compliance_audit.py

echo "Running Trivy container vulnerability scan..."
bash security_suite/trivy_scan.sh

echo "All compliance checks passed."
