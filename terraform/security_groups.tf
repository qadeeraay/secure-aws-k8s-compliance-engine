# ==============================================================================
# Tiered Stateful Security Groups & Microsegmentation
# Using standalone AWS Security Group Rules to eliminate cyclic dependencies
# Compliance Mappings:
# - NIST SP 800-53 R5: SC-7 (Boundary Protection), AC-4 (Information Flow Enforcement)
# - ISO 27002:2022: Control 8.20 (Network Security), Control 8.22 (Segregation of Networks)
# - SOC 2 Type II: CC6.6 (Boundary Protection)
# - PCI DSS v4.0: Requirement 1.2, 1.3 (Restricted Ingress/Egress & Protocol Filtering)
# ==============================================================================

# ------------------------------------------------------------------------------
# 1. Public Ingress Tier Security Group (ALB / Gateway)
# ------------------------------------------------------------------------------
resource "aws_security_group" "ingress_tier" {
  # checkov:skip=CKV2_AWS_5: Reference architecture security group attached to downstream workloads during cluster deployment
  name        = "${var.project_name}-ingress-sg"
  description = "Security group for public HTTPS ingress gateway with TLS termination"
  vpc_id      = aws_vpc.main.id

  tags = {
    Name = "${var.project_name}-ingress-sg"
  }
}

resource "aws_vpc_security_group_ingress_rule" "ingress_https" {
  security_group_id = aws_security_group.ingress_tier.id
  description       = "Allow inbound HTTPS from internet"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_vpc_security_group_egress_rule" "ingress_to_compute" {
  security_group_id            = aws_security_group.ingress_tier.id
  description                  = "Forward traffic exclusively to private compute tier on port 8080"
  ip_protocol                  = "tcp"
  from_port                    = 8080
  to_port                      = 8080
  referenced_security_group_id = aws_security_group.compute_tier.id
}

# ------------------------------------------------------------------------------
# 2. Private Compute / Kubernetes Pod Tier Security Group
# ------------------------------------------------------------------------------
resource "aws_security_group" "compute_tier" {
  # checkov:skip=CKV2_AWS_5: Reference architecture security group attached to downstream workloads during cluster deployment
  name        = "${var.project_name}-compute-sg"
  description = "Security group for private Kubernetes worker nodes and application workloads"
  vpc_id      = aws_vpc.main.id

  tags = {
    Name = "${var.project_name}-compute-sg"
  }
}

resource "aws_vpc_security_group_ingress_rule" "compute_from_ingress" {
  security_group_id            = aws_security_group.compute_tier.id
  description                  = "Allow inbound HTTP only from ingress ALB tier"
  ip_protocol                  = "tcp"
  from_port                    = 8080
  to_port                      = 8080
  referenced_security_group_id = aws_security_group.ingress_tier.id
}

resource "aws_vpc_security_group_egress_rule" "compute_to_database" {
  security_group_id            = aws_security_group.compute_tier.id
  description                  = "Allow outbound PostgreSQL connection exclusively to isolated database tier"
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
  referenced_security_group_id = aws_security_group.database_tier.id
}

resource "aws_vpc_security_group_egress_rule" "compute_to_aws_apis" {
  security_group_id = aws_security_group.compute_tier.id
  description       = "Allow outbound HTTPS for AWS service API communication via endpoints"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = var.vpc_cidr
}

# ------------------------------------------------------------------------------
# 3. Isolated Air-Gapped Database Tier Security Group
# ------------------------------------------------------------------------------
resource "aws_security_group" "database_tier" {
  # checkov:skip=CKV2_AWS_5: Reference architecture security group attached to downstream workloads during cluster deployment
  name        = "${var.project_name}-database-sg"
  description = "Security group for air-gapped database tier with zero internet connectivity"
  vpc_id      = aws_vpc.main.id

  tags = {
    Name = "${var.project_name}-database-sg"
  }
}

resource "aws_vpc_security_group_ingress_rule" "database_from_compute" {
  security_group_id            = aws_security_group.database_tier.id
  description                  = "Allow PostgreSQL access strictly from authorized compute tier"
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
  referenced_security_group_id = aws_security_group.compute_tier.id
}

output "ingress_sg_id" {
  description = "ID of the ingress security group"
  value       = aws_security_group.ingress_tier.id
}

output "compute_sg_id" {
  description = "ID of the compute security group"
  value       = aws_security_group.compute_tier.id
}

output "database_sg_id" {
  description = "ID of the database security group"
  value       = aws_security_group.database_tier.id
}
