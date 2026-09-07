# ==============================================================================
# AWS KMS Customer Managed Key (CMK)
# Compliance Mappings:
# - NIST SP 800-53 R5: SC-12 (Cryptographic Key Establishment), SC-28 (Protection at Rest)
# - ISO 27002:2022: Control 8.24 (Use of Cryptography)
# - SOC 2 Type II: CC6.6, CC6.7 (Logical Boundary Protection & Encryption)
# - PCI DSS v4.0: Requirement 3.4, 3.5 (Protect Stored Account Data)
# - FIPS 140-2 / 140-3: Level 2 / Level 3 Hardware Security Module (HSM) Backed
# ==============================================================================

data "aws_caller_identity" "current" {}

resource "aws_kms_key" "primary" {
  description             = "FIPS 140-2/3 Level 2/3 Validated Primary CMK with Automated Annual Key Rotation"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  customer_master_key_spec = "SYMMETRIC_DEFAULT" # AES-256-GCM compliant
  key_usage                = "ENCRYPT_DECRYPT"

  policy = jsonencode({
    Version = "2012-10-17"
    Id      = "EnterpriseComplianceKMSPolicy"
    Statement = [
      {
        Sid    = "EnableRootKeyAdministration"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowCloudWatchLogsEncryption"
        Effect = "Allow"
        Principal = {
          Service = "logs.${var.aws_region}.amazonaws.com"
        }
        Action = [
          "kms:Encrypt*",
          "kms:Decrypt*",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:Describe*"
        ]
        Resource = "*"
        Condition = {
          ArnEquals = {
            "kms:EncryptionContext:aws:logs:arn" = "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:*"
          }
        }
      },
      {
        Sid    = "AllowS3AndVPCFlowLogsServiceEncryption"
        Effect = "Allow"
        Principal = {
          Service = [
            "s3.amazonaws.com",
            "delivery.logs.amazonaws.com"
          ]
        }
        Action = [
          "kms:GenerateDataKey*",
          "kms:Decrypt"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Name        = "${var.project_name}-primary-cmk"
    FIPSVersion = "FIPS-140-2-L2/L3"
    KeyType     = "CustomerManagedKey"
  }
}

resource "aws_kms_alias" "primary" {
  name          = "alias/${var.project_name}-primary-key"
  target_key_id = aws_kms_key.primary.key_id
}

output "kms_key_arn" {
  description = "ARN of the primary FIPS-compliant KMS CMK"
  value       = aws_kms_key.primary.arn
}

output "kms_key_id" {
  description = "ID of the primary KMS CMK"
  value       = aws_kms_key.primary.key_id
}
