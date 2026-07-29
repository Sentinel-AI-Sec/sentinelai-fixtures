# --- Crown jewel: reachable via order_task_role's s3:* grant ------------

resource "aws_s3_bucket" "customer_data" {
  bucket = "sentinelai-fixture-customer-data"
}

# VULN (INFRA-02): no server-side encryption configured.
# Checkov: CKV_AWS_19
# (intentionally no aws_s3_bucket_server_side_encryption_configuration block)

# VULN (INFRA-03): bucket public access block disabled / permissive ACL.
# Checkov: CKV_AWS_53 / CKV_AWS_54 / CKV_AWS_55 / CKV_AWS_56
resource "aws_s3_bucket_public_access_block" "customer_data_pab" {
  bucket = aws_s3_bucket.customer_data.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# VULN (INFRA-04): versioning disabled.
# Checkov: CKV_AWS_21
resource "aws_s3_bucket_versioning" "customer_data_versioning" {
  bucket = aws_s3_bucket.customer_data.id
  versioning_configuration {
    status = "Disabled"
  }
}

# --- Orphaned bucket: a real misconfig, but no role can reach it --------
# Noise finding: Trivy/Checkov will flag this, but it never becomes part
# of a reachable chain, so Blue/Reporter should demote it.

resource "aws_s3_bucket" "build_artifacts_orphan" {
  bucket = "sentinelai-fixture-build-artifacts-unused"
}

resource "aws_s3_bucket_versioning" "build_artifacts_orphan_versioning" {
  bucket = aws_s3_bucket.build_artifacts_orphan.id
  versioning_configuration {
    status = "Disabled"
  }
}
