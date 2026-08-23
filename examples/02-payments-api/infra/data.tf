# The crown jewels: the PSP credential the flagship chain ends at, and the ledger beside it.

# INFRA-10 (CWE-311): the secret is stored without a customer-managed key, so it is protected
# only by the AWS-managed default. Combined with INFRA-01's wildcard read, anyone who reaches
# the task role reads it in plaintext.
resource "aws_secretsmanager_secret" "psp_live_key" {
  name = "prod/psp/live-key"

  # INFRA-11 (CWE-404): no recovery window, so a deletion is immediate and unrecoverable.
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "psp_live_key" {
  secret_id = aws_secretsmanager_secret.psp_live_key.id

  # Dummy fixture value - never a real credential.
  secret_string = jsonencode({
    live_key = "psp_live_fixture_dummy_key_000111"
  })
}

resource "aws_db_instance" "ledger" {
  identifier     = "payments-ledger"
  engine         = "postgres"
  engine_version = "13.4"
  instance_class = "db.t3.medium"
  username       = "svc_payments"

  # Dummy fixture value.
  password = "P@ymentsFixture123"

  # INFRA-12 (CWE-311): storage is not encrypted at rest.
  storage_encrypted = false

  # INFRA-13 (CWE-668): the ledger is publicly addressable. With INFRA-07's 0.0.0.0/0 on 5432,
  # that is a direct path to the payment records that does not involve the application at all.
  publicly_accessible = true

  # INFRA-14 (CWE-778): no audit logging exported.
  enabled_cloudwatch_logs_exports = []

  # INFRA-15: backups disabled.
  backup_retention_period = 0

  skip_final_snapshot = true
}

# INFRA-16 (CWE-778): the account has no trail, so none of the above leaves a record. Included
# because "the attack is invisible" is a finding in its own right and one that only shows up
# when the graph is read as a whole rather than resource by resource.
resource "aws_cloudtrail" "payments" {
  name                          = "payments-trail"
  s3_bucket_name                = "payments-trail-logs"
  include_global_service_events = false
  is_multi_region_trail         = false
  enable_logging                = false
}
