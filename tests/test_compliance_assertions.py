#!/usr/bin/env python3
"""
Unit & Assertion Test Suite for Cloud Compliance & DevSecOps Hardening
Verifies that critical compliance controls remain immutable in source code.
"""

import unittest
import os
import re

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TERRAFORM_DIR = os.path.join(REPO_ROOT, "terraform")
KUBERNETES_DIR = os.path.join(REPO_ROOT, "kubernetes")

class TestComplianceGuardrails(unittest.TestCase):

    def test_kms_cmk_rotation_enabled(self):
        """Verify NIST SC-12 & PCI DSS 3.5: KMS key rotation is explicitly true."""
        kms_path = os.path.join(TERRAFORM_DIR, "kms.tf")
        with open(kms_path, "r") as f:
            content = f.read()
        self.assertIn("enable_key_rotation", content)
        self.assertRegex(content, r"enable_key_rotation\s*=\s*true")

    def test_s3_tls_transport_enforced(self):
        """Verify NIST SC-8 & PCI DSS 4.1: S3 bucket policy denies non-TLS requests."""
        s3_path = os.path.join(TERRAFORM_DIR, "s3.tf")
        with open(s3_path, "r") as f:
            content = f.read()
        self.assertIn("aws:SecureTransport", content)
        self.assertIn("EnforceTLSRequestsOnly", content)

    def test_s3_public_access_block_complete(self):
        """Verify SOC 2 CC6.1 & ISO 27002 5.15: All 4 public access block flags are true."""
        s3_path = os.path.join(TERRAFORM_DIR, "s3.tf")
        with open(s3_path, "r") as f:
            content = f.read()
        self.assertIn("block_public_acls       = true", content)
        self.assertIn("block_public_policy     = true", content)
        self.assertIn("ignore_public_acls      = true", content)
        self.assertIn("restrict_public_buckets = true", content)

    def test_k8s_non_root_and_high_uid(self):
        """Verify NIST CM-7 & PCI DSS 2.2: K8s pod executes as non-root with UID > 10000."""
        dep_path = os.path.join(KUBERNETES_DIR, "deployment.yaml")
        with open(dep_path, "r") as f:
            content = f.read()
        self.assertIn("runAsNonRoot: true", content)
        self.assertIn("runAsUser: 10001", content)

    def test_k8s_read_only_rootfs_and_capabilities_dropped(self):
        """Verify SOC 2 CC6.6: K8s pod rootfs is immutable and all Linux capabilities dropped."""
        dep_path = os.path.join(KUBERNETES_DIR, "deployment.yaml")
        with open(dep_path, "r") as f:
            content = f.read()
        self.assertIn("readOnlyRootFilesystem: true", content)
        self.assertIn("allowPrivilegeEscalation: false", content)
        self.assertIn("- ALL", content)

    def test_cloudwatch_compliance_retention(self):
        """Verify PCI DSS 10.7 & NIST AU-11: Audit log retention is >= 365 days."""
        var_path = os.path.join(TERRAFORM_DIR, "variables.tf")
        with open(var_path, "r") as f:
            content = f.read()
        self.assertRegex(content, r"default\s*=\s*365")

if __name__ == "__main__":
    unittest.main()
