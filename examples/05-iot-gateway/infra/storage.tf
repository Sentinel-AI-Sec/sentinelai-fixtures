# The firmware bucket. This is what the whole fixture is about.

provider "aws" {
  region = var.region
}

resource "aws_s3_bucket" "firmware" {
  bucket = "iot-fleet-firmware"
}

# INFRA-01 (flagship, CWE-284): the bucket policy allows s3:PutObject from Principal "*".
#
# Anyone on the internet can write an object into the bucket the entire fleet installs from.
# Combined with CODE-05 - which reads the manifest's signature field and never checks it - this
# is unauthenticated remote code execution on every device in the field, delivered through the
# vendor's own update channel.
#
# The GetObject grant beside it is intentional and correct: devices need to read firmware
# anonymously. The PutObject grant is the mistake, and the two sitting in one statement is why
# it survived review.
resource "aws_s3_bucket_policy" "firmware" {
  bucket = aws_s3_bucket.firmware.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "FleetReadAndPublish"
        Effect    = "Allow"
        Principal = "*"
        Action = [
          "s3:GetObject",
          "s3:PutObject"
        ]
        Resource = "arn:aws:s3:::iot-fleet-firmware/*"
      }
    ]
  })
}

# INFRA-02 (CWE-284): public access block fully disabled, which is what lets the policy above
# take effect at all. With this on, INFRA-01 would be inert - so the two together are the
# finding, and either one alone is not.
resource "aws_s3_bucket_public_access_block" "firmware" {
  bucket = aws_s3_bucket.firmware.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# INFRA-03 (CWE-353): versioning disabled, so overwriting a firmware image destroys the
# original. There is no way to tell what the fleet was told to install last week, or to roll
# back to it.
resource "aws_s3_bucket_versioning" "firmware" {
  bucket = aws_s3_bucket.firmware.id

  versioning_configuration {
    status = "Suspended"
  }
}

# INFRA-04 (CWE-778): no access logging, so a firmware replacement leaves no record of who
# wrote it or when.
resource "aws_s3_bucket_logging" "firmware" {
  bucket        = aws_s3_bucket.firmware.id
  target_bucket = ""
  target_prefix = ""
}

# INFRA-11 (CWE-311): bucket keys disabled and no customer-managed key.
resource "aws_s3_bucket_server_side_encryption_configuration" "firmware" {
  bucket = aws_s3_bucket.firmware.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = false
  }
}

# Noise: a correctly-locked bucket holding build logs. Present so the fixture can distinguish a
# bucket that was configured from one that was not.
resource "aws_s3_bucket" "build_logs" {
  bucket = "iot-fleet-build-logs"
}

resource "aws_s3_bucket_public_access_block" "build_logs" {
  bucket = aws_s3_bucket.build_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
