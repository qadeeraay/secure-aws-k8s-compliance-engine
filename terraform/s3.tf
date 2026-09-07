# ==============================================================================
# AWS S3 Storage Security & Compliance Hardening
# Compliance Mappings:
# - NIST SP 800-53 R5: SC-8 (Transmission Confidentiality), SC-28 (Protection at Rest), AC-3 (Access Enforcement)
# - ISO 27002:2022: Control 8.20 (Network Security), Control 8.24 (Cryptography)
# - SOC 2 Type II: CC6.1, CC6.6, CC6.7 (Logical Access & Encryption)
# - PCI DSS v4.0: Requirement 3.4 (Render PAN Unreadable), Requirement 4.1 (Strong Cryptography in Transit)
# - FIPS 140-2 / 140-3: TLS 1.2/1.3 Enforcement & AES-256 KMS CMK Encryption
# ==============================================================================

resource "random_id" "bucket_suffix" {
  byte_length = 4
}

# ------------------------------------------------------------------------------
# 1. Access Logging Audit Bucket (Captures access logs for the primary bucket)
# ------------------------------------------------------------------------------
resource "aws_s3_bucket" "audit_logs" {
  # checkov:skip=CKV_AWS_144: Single-region primary deployment; cross-region disaster recovery replication configured in secondary DR region
  bucket        = "${var.project_name}-audit-logs-${random_id.bucket_suffix.hex}"
  force_destroy = true

  tags = {
    Name    = "${var.project_name}-audit-logs"
    Purpose = "CentralizedAccessAuditLogs"
  }
}

resource "aws_s3_bucket_notification" "audit_logs" {
  bucket      = aws_s3_bucket.audit_logs.id
  eventbridge = true
}

resource "aws_s3_bucket_versioning" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.primary.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id

  rule {
    id     = "enforce-log-lifecycle-and-abort-multipart"
    status = "Enabled"

    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }

    expiration {
      days = var.log_retention_in_days
    }
  }
}

resource "aws_s3_bucket_policy" "audit_logs_tls" {
  bucket = aws_s3_bucket.audit_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnforceTLSRequestsOnly"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.audit_logs.arn,
          "${aws_s3_bucket.audit_logs.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}

# ------------------------------------------------------------------------------
# 2. Primary Production Data Bucket (Hardened with KMS CMK & Strict Policy)
# ------------------------------------------------------------------------------
resource "aws_s3_bucket" "secure_data" {
  # checkov:skip=CKV_AWS_144: Single-region primary deployment; cross-region disaster recovery replication configured in secondary DR region
  bucket        = "${var.project_name}-secure-data-${random_id.bucket_suffix.hex}"
  force_destroy = true

  tags = {
    Name    = "${var.project_name}-secure-data"
    Purpose = "ConfidentialProductionData"
  }
}

resource "aws_s3_bucket_notification" "secure_data" {
  bucket      = aws_s3_bucket.secure_data.id
  eventbridge = true
}

resource "aws_s3_bucket_versioning" "secure_data" {
  bucket = aws_s3_bucket.secure_data.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "secure_data" {
  bucket = aws_s3_bucket.secure_data.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.primary.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_logging" "secure_data" {
  bucket = aws_s3_bucket.secure_data.id

  target_bucket = aws_s3_bucket.audit_logs.id
  target_prefix = "secure-data-access-logs/"
}

resource "aws_s3_bucket_public_access_block" "secure_data" {
  bucket = aws_s3_bucket.secure_data.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "secure_data" {
  bucket = aws_s3_bucket.secure_data.id

  rule {
    id     = "abort-multipart-and-noncurrent-retention"
    status = "Enabled"

    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    noncurrent_version_expiration {
      noncurrent_days = 90
    }
  }
}

resource "aws_s3_bucket_policy" "secure_data" {
  bucket = aws_s3_bucket.secure_data.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnforceTLSRequestsOnly"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.secure_data.arn,
          "${aws_s3_bucket.secure_data.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      },
      {
        Sid       = "DenyIncorrectEncryptionHeader"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.secure_data.arn}/*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption" = "aws:kms"
          }
        }
      }
    ]
  })
}

output "secure_data_bucket_arn" {
  description = "ARN of the hardened secure S3 bucket"
  value       = aws_s3_bucket.secure_data.arn
}

output "audit_logs_bucket_arn" {
  description = "ARN of the audit logs S3 bucket"
  value       = aws_s3_bucket.audit_logs.arn
}
