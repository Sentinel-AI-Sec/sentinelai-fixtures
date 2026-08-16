# Near-miss clean sample (SEC-38 clean-samples).
# RESEMBLES: the flagship crown-jewel bucket (INFRA-02/03/04: no encryption at rest, public
#            access, no versioning).
# WHY IT'S SAFE: this bucket is private with a full public-access block, KMS server-side
#            encryption, versioning enabled, and access logging to a separate log bucket -
#            the hardened counterpart of the crown-jewel bucket.
resource "aws_s3_bucket" "secure_data" {
  bucket = "secure-order-data-bucket"
}

resource "aws_s3_bucket_public_access_block" "secure_data" {
  bucket                  = aws_s3_bucket.secure_data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "secure_data" {
  bucket = aws_s3_bucket.secure_data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "secure_data" {
  bucket = aws_s3_bucket.secure_data.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_logging" "secure_data" {
  bucket        = aws_s3_bucket.secure_data.id
  target_bucket = "secure-access-logs-bucket"
  target_prefix = "s3-access/"
}
