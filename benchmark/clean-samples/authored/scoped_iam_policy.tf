# Near-miss clean sample (SEC-38 clean-samples).
# RESEMBLES: the flagship INFRA-01 wildcard IAM (aws_iam_role_policy.order_task_policy) with
#            Action "s3:*" and Resource "*" (CWE-284 over-permissive access).
# WHY IT'S SAFE: both the actions and the resource ARNs are explicitly scoped - a read-only
#            pair of actions against one named bucket. No wildcard action, no wildcard resource.
resource "aws_iam_policy" "scoped_order_reader" {
  name        = "scoped-order-reader"
  description = "Read-only access to a single orders bucket - least privilege."

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadOrdersBucketOnly"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          "arn:aws:s3:::orders-data-bucket",
          "arn:aws:s3:::orders-data-bucket/*"
        ]
      }
    ]
  })
}
