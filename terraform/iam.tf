# ==============================================================================
# Least-Privilege IAM Roles & Scoped Policies (Zero Wildcards)
# Compliance Mappings:
# - NIST SP 800-53 R5: AC-2 (Account Management), AC-3 (Access Enforcement), AC-6 (Least Privilege)
# - ISO 27002:2022: Control 5.15 (Access Control), Control 5.18 (Access Rights)
# - SOC 2 Type II: CC6.1, CC6.3 (Logical Access Restrictions)
# - PCI DSS v4.0: Requirement 7.1, 7.2 (Restrict Access to System Components & Data)
# ==============================================================================

# ------------------------------------------------------------------------------
# 1. IAM Role for Kubernetes Service Account (IRSA Pattern)
# ------------------------------------------------------------------------------
resource "aws_iam_role" "k8s_workload_role" {
  name        = "${var.project_name}-k8s-workload-role"
  description = "Scoped IAM role assumed strictly by Kubernetes service accounts via OIDC"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowK8sServiceAccountAssumeRole"
        Effect = "Allow"
        Principal = {
          Federated = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/oidc.eks.${var.aws_region}.amazonaws.com/id/EXAMPLE"
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "oidc.eks.${var.aws_region}.amazonaws.com/id/EXAMPLE:sub" = "system:serviceaccount:compliance-workload:secure-api-sa"
            "oidc.eks.${var.aws_region}.amazonaws.com/id/EXAMPLE:aud" = "sts.amazonaws.com"
          }
        }
      }
    ]
  })

  tags = {
    Name = "${var.project_name}-k8s-workload-role"
  }
}

# ------------------------------------------------------------------------------
# 2. Scoped S3 & KMS Least-Privilege Policy (No Wildcard Actions or Resources)
# ------------------------------------------------------------------------------
resource "aws_iam_policy" "k8s_workload_policy" {
  name        = "${var.project_name}-k8s-workload-policy"
  description = "Least-privilege policy granting scoped S3 data read/write and KMS cryptographic operations"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ScopedS3ObjectActions"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.secure_data.arn,
          "${aws_s3_bucket.secure_data.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "true"
          }
        }
      },
      {
        Sid    = "ScopedKMSCryptographicActions"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:DescribeKey"
        ]
        Resource = [
          aws_kms_key.primary.arn
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "k8s_workload" {
  role       = aws_iam_role.k8s_workload_role.name
  policy_arn = aws_iam_policy.k8s_workload_policy.arn
}

output "k8s_workload_role_arn" {
  description = "ARN of the scoped Kubernetes workload IAM role"
  value       = aws_iam_role.k8s_workload_role.arn
}
