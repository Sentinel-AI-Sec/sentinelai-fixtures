# --- Flagship role: reachable from order-task, over-permissioned --------

resource "aws_iam_role" "order_task_role" {
  name = "order-task-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })
}

# VULN (INFRA-01 - flagship): wildcard action + wildcard resource.
# Checkov: CKV_AWS_* (IAM policy allows * action / * resource)
# rule_mappings resolves this check_id -> CWE-284 (Improper Access Control).
# This is the edge order_task_role.arn --can-access--> S3 customer-data,
# confidence = "certain" (explicit inline policy statement).
resource "aws_iam_role_policy" "order_task_policy" {
  name = "order-task-s3-access"
  role = aws_iam_role.order_task_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "s3:*"
        Resource = "*"
      }
    ]
  })
}

# --- Legacy worker role: isolated, does NOT reach the crown jewel -------
# Kept deliberately narrow so it never chains anywhere - noise for the
# false-positive-reduction / demotion story, not a real path.

resource "aws_iam_role" "legacy_worker_role" {
  name = "legacy-worker-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "legacy_worker_policy" {
  name = "legacy-worker-logs-only"
  role = aws_iam_role.legacy_worker_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:*:*:log-group:/ecs/legacy-worker:*"
      }
    ]
  })
}
