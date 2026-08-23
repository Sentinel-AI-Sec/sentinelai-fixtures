# IAM for the payments service.
#
# INFRA-01 is the far end of the flagship chain: credentials stolen through CODE-01's SSRF are
# this role's credentials, and this role can read every secret in the account.

resource "aws_iam_role" "payments_task_role" {
  name = "payments-task-role"

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

# INFRA-01 (flagship, CWE-284): wildcard resource on a secrets-reading action.
#
# The service needs exactly one secret - prod/psp/live-key, which SecretsClient names. This
# grants every secret in the account, so the blast radius of the SSRF is the whole secret store
# rather than one payment key. Checkov: CKV_AWS_290 / CKV_AWS_355.
resource "aws_iam_role_policy" "payments_secrets_policy" {
  name = "payments-secrets-policy"
  role = aws_iam_role.payments_task_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret",
          "kms:Decrypt"
        ]
        Resource = "*"
      }
    ]
  })
}

# INFRA-02 (CWE-269): the same role can also assume any other role in the account, which turns
# one stolen credential into lateral movement across every service.
resource "aws_iam_role_policy" "payments_assume_policy" {
  name = "payments-assume-policy"
  role = aws_iam_role.payments_task_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "sts:AssumeRole"
        Resource = "*"
      }
    ]
  })
}

# INFRA-03 (CWE-732): the deploy user has AdministratorAccess attached directly. Not on the
# flagship chain - nothing in the application can reach it - but a real finding, and one a
# reasoner should rank below the chain rather than above it on severity alone.
resource "aws_iam_user" "ci_deployer" {
  name = "payments-ci-deployer"
}

resource "aws_iam_user_policy_attachment" "ci_deployer_admin" {
  user       = aws_iam_user.ci_deployer.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# Noise: a role that exists, is over-permissive, and is reachable from nothing. Included so the
# fixture can distinguish "unreachable finding" from "no finding".
resource "aws_iam_role" "orphaned_batch_role" {
  name = "payments-orphaned-batch-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action    = "sts:AssumeRole"
        Effect    = "Allow"
        Principal = { Service = "batch.amazonaws.com" }
      }
    ]
  })
}

resource "aws_iam_role_policy" "orphaned_batch_policy" {
  name = "payments-orphaned-batch-policy"
  role = aws_iam_role.orphaned_batch_role.id

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
