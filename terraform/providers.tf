terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.40.0"
    }
  }
}

variable "aws_region" {
  type        = string
  description = "Target AWS Region"
  default     = "us-east-1"
}

variable "environment" {
  type        = string
  description = "Deployment environment (production, staging, dev)"
  default     = "production"
}

variable "use_localstack" {
  type        = bool
  description = "Toggle LocalStack emulation for zero-cost local DevSecOps testing"
  default     = true
}

variable "localstack_endpoint" {
  type        = string
  description = "LocalStack endpoint URL"
  default     = "http://localhost:4566"
}

provider "aws" {
  region                      = var.aws_region
  access_key                  = var.use_localstack ? "mock_access_key" : null
  secret_key                  = var.use_localstack ? "mock_secret_key" : null
  skip_credentials_validation = var.use_localstack
  skip_metadata_api_check     = var.use_localstack
  skip_requesting_account_id  = var.use_localstack

  default_tags {
    tags = {
      Environment         = var.environment
      Project             = "secure-aws-k8s-compliance-engine"
      ManagedBy           = "Terraform"
      ComplianceFramework = "NIST-800-53-R5,ISO-27002,SOC2-Type2,PCI-DSS-v4.0,FIPS-140"
      DataClassification  = "Confidential"
    }
  }

  dynamic "endpoints" {
    for_each = var.use_localstack ? [1] : []
    content {
      kms        = var.localstack_endpoint
      s3         = var.localstack_endpoint
      iam        = var.localstack_endpoint
      logs       = var.localstack_endpoint
      ec2        = var.localstack_endpoint
      sts        = var.localstack_endpoint
      cloudwatch = var.localstack_endpoint
    }
  }
}
