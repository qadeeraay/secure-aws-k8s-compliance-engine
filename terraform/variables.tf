variable "project_name" {
  type        = string
  description = "Project name prefix for resources"
  default     = "compliance-engine"
}

variable "vpc_cidr" {
  type        = string
  description = "CIDR block for the multi-tier VPC"
  default     = "10.100.0.0/16"
}

variable "availability_zones" {
  type        = list(string)
  description = "Availability zones for high availability"
  default     = ["us-east-1a", "us-east-1b"]
}

variable "public_subnet_cidrs" {
  type        = list(string)
  description = "CIDR blocks for public ingress subnets"
  default     = ["10.100.1.0/24", "10.100.2.0/24"]
}

variable "private_compute_subnet_cidrs" {
  type        = list(string)
  description = "CIDR blocks for private compute / Kubernetes worker subnets"
  default     = ["10.100.10.0/24", "10.100.20.0/24"]
}

variable "isolated_database_subnet_cidrs" {
  type        = list(string)
  description = "CIDR blocks for air-gapped database subnets with no internet route"
  default     = ["10.100.100.0/24", "10.100.200.0/24"]
}

variable "log_retention_in_days" {
  type        = number
  description = "CloudWatch log retention in days (Mandated >= 365 for PCI DSS Req 10.7 & NIST AU-11)"
  default     = 365
}
