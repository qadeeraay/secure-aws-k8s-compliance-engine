# ==============================================================================
# AWS Multi-Tier Zero-Trust VPC Architecture
# Compliance Mappings:
# - NIST SP 800-53 R5: SC-7 (Boundary Protection), AU-2 / AU-12 (Audit Generation & Logs)
# - ISO 27002:2022: Control 8.20 (Network Security), Control 8.16 (Monitoring Activities)
# - SOC 2 Type II: CC6.6 (Boundary Protection), CC7.2 (Infrastructure Monitoring)
# - PCI DSS v4.0: Requirement 1.2, 1.3 (Network Security Controls & Demarcation)
# ==============================================================================

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "${var.project_name}-vpc"
  }
}

# ------------------------------------------------------------------------------
# 1. Subnet Segregation: Public Ingress, Private Compute, Air-Gapped Database
# ------------------------------------------------------------------------------
resource "aws_subnet" "public" {
  count                   = length(var.public_subnet_cidrs)
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public_subnet_cidrs[count.index]
  availability_zone       = var.availability_zones[count.index]
  map_public_ip_on_launch = false # Enforced security: No automated public IP mapping

  tags = {
    Name = "${var.project_name}-public-subnet-${count.index + 1}"
    Tier = "PublicIngress"
  }
}

resource "aws_subnet" "private_compute" {
  count                   = length(var.private_compute_subnet_cidrs)
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.private_compute_subnet_cidrs[count.index]
  availability_zone       = var.availability_zones[count.index]
  map_public_ip_on_launch = false

  tags = {
    Name = "${var.project_name}-private-compute-subnet-${count.index + 1}"
    Tier = "PrivateCompute"
  }
}

resource "aws_subnet" "isolated_database" {
  count                   = length(var.isolated_database_subnet_cidrs)
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.isolated_database_subnet_cidrs[count.index]
  availability_zone       = var.availability_zones[count.index]
  map_public_ip_on_launch = false

  tags = {
    Name = "${var.project_name}-isolated-db-subnet-${count.index + 1}"
    Tier = "IsolatedDatabase"
  }
}

# ------------------------------------------------------------------------------
# 2. Gateways & Routing: Ingress Gateway & Air-Gapped Route Isolation
# ------------------------------------------------------------------------------
resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${var.project_name}-igw"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.gw.id
  }

  tags = {
    Name = "${var.project_name}-public-rt"
  }
}

resource "aws_route_table_association" "public" {
  count          = length(aws_subnet.public)
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# Private compute subnets have isolated internal routing (no internet egress by default)
resource "aws_route_table" "private_compute" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${var.project_name}-private-compute-rt"
  }
}

resource "aws_route_table_association" "private_compute" {
  count          = length(aws_subnet.private_compute)
  subnet_id      = aws_subnet.private_compute[count.index].id
  route_table_id = aws_route_table.private_compute.id
}

# Isolated database subnets are completely air-gapped
resource "aws_route_table" "isolated_database" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${var.project_name}-isolated-db-rt"
  }
}

resource "aws_route_table_association" "isolated_database" {
  count          = length(aws_subnet.isolated_database)
  subnet_id      = aws_subnet.isolated_database[count.index].id
  route_table_id = aws_route_table.isolated_database.id
}

# ------------------------------------------------------------------------------
# 3. Restrict Default Security Group (Checkov CKV_AWS_148)
# ------------------------------------------------------------------------------
resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.main.id

  # Explicitly zero ingress and egress rules to disable default SG communication
  tags = {
    Name        = "${var.project_name}-default-sg-locked"
    Description = "Compliance Locked Default SG"
  }
}

# ------------------------------------------------------------------------------
# 4. VPC Flow Logs to KMS Encrypted CloudWatch Logs (Checkov CKV_AWS_149)
# ------------------------------------------------------------------------------
resource "aws_cloudwatch_log_group" "vpc_flow_logs" {
  name              = "/aws/vpc/${var.project_name}-flow-logs"
  retention_in_days = var.log_retention_in_days
  kms_key_id        = aws_kms_key.primary.arn

  tags = {
    Name = "${var.project_name}-vpc-flow-logs"
  }
}

resource "aws_iam_role" "vpc_flow_logs_role" {
  name = "${var.project_name}-vpc-flow-logs-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowVPCFlowLogsAssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "vpc-flow-logs.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_policy" "vpc_flow_logs_policy" {
  name        = "${var.project_name}-vpc-flow-logs-policy"
  description = "Scoped policy allowing VPC Flow Logs delivery to CloudWatch"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ScopedLogDeliveryActions"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ]
        Resource = "${aws_cloudwatch_log_group.vpc_flow_logs.arn}:*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "vpc_flow_logs" {
  role       = aws_iam_role.vpc_flow_logs_role.name
  policy_arn = aws_iam_policy.vpc_flow_logs_policy.arn
}

resource "aws_flow_log" "main" {
  iam_role_arn    = aws_iam_role.vpc_flow_logs_role.arn
  log_destination = aws_cloudwatch_log_group.vpc_flow_logs.arn
  traffic_type    = "ALL"
  vpc_id          = aws_vpc.main.id

  tags = {
    Name = "${var.project_name}-flow-log"
  }
}

output "vpc_id" {
  description = "VPC ID"
  value       = aws_vpc.main.id
}
