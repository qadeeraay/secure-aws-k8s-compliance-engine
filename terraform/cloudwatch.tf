# ==============================================================================
# CloudWatch Centralized Audit Telemetry & CIS Benchmark Alarms
# Compliance Mappings:
# - NIST SP 800-53 R5: AU-2, AU-6, AU-12 (Audit Event Collection, Review & Analysis)
# - ISO 27002:2022: Control 8.15 (Logging), Control 8.16 (Monitoring Activities)
# - SOC 2 Type II: CC7.2, CC7.3 (Continuous Monitoring & Anomaly Detection)
# - PCI DSS v4.0: Requirement 10.1, 10.2, 10.7 (Audit Logging & Retention >= 365 Days)
# ==============================================================================

resource "aws_cloudwatch_log_group" "application_audit" {
  name              = "/aws/app/${var.project_name}-audit-trail"
  retention_in_days = var.log_retention_in_days
  kms_key_id        = aws_kms_key.primary.arn

  tags = {
    Name        = "${var.project_name}-application-audit"
    Compliance  = "PCI-DSS-Req10-Retention-365"
    DataPrivacy = "AuditTrails"
  }
}

# ------------------------------------------------------------------------------
# 1. CIS Metric Filter: Unauthorized API Calls Detection
# ------------------------------------------------------------------------------
resource "aws_cloudwatch_log_metric_filter" "unauthorized_api_calls" {
  name           = "UnauthorizedAPICalls"
  pattern        = "{($.errorCode = \"*UnauthorizedOperation\") || ($.errorCode = \"AccessDenied*\")}"
  log_group_name = aws_cloudwatch_log_group.application_audit.name

  metric_transformation {
    name      = "UnauthorizedAPICallsMetric"
    namespace = "CISBenchmark"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "unauthorized_api_calls" {
  alarm_name          = "${var.project_name}-unauthorized-api-calls-alarm"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = aws_cloudwatch_log_metric_filter.unauthorized_api_calls.metric_transformation[0].name
  namespace           = aws_cloudwatch_log_metric_filter.unauthorized_api_calls.metric_transformation[0].namespace
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "Triggered immediately when unauthorized AWS API calls or AccessDenied events occur"
  treat_missing_data  = "notBreaching"
}

# ------------------------------------------------------------------------------
# 2. CIS Metric Filter: IAM Policy Changes
# ------------------------------------------------------------------------------
resource "aws_cloudwatch_log_metric_filter" "iam_policy_changes" {
  name           = "IAMPolicyChanges"
  pattern        = "{($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventName=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolicy)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=DeletePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersion)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.eventName=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGroupPolicy)||($.eventName=DetachGroupPolicy)}"
  log_group_name = aws_cloudwatch_log_group.application_audit.name

  metric_transformation {
    name      = "IAMPolicyChangesMetric"
    namespace = "CISBenchmark"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "iam_policy_changes" {
  alarm_name          = "${var.project_name}-iam-policy-changes-alarm"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = aws_cloudwatch_log_metric_filter.iam_policy_changes.metric_transformation[0].name
  namespace           = aws_cloudwatch_log_metric_filter.iam_policy_changes.metric_transformation[0].namespace
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "Triggered when any IAM policy or role assignment is modified"
  treat_missing_data  = "notBreaching"
}

output "audit_log_group_arn" {
  description = "ARN of the encrypted audit CloudWatch log group"
  value       = aws_cloudwatch_log_group.application_audit.arn
}
