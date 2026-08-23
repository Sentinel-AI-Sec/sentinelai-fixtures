# The archive holding patient documents. This is the crown jewel of fixture 03, and the reason
# the auth bypass in CODE-01 is only the *convenient* path to it rather than the only one.

provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "portal" {
  name     = "rg-patient-portal"
  location = var.location
}

resource "azurerm_storage_account" "archive" {
  name                     = "phiportalarchive"
  resource_group_name      = azurerm_resource_group.portal.name
  location                 = azurerm_resource_group.portal.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  # INFRA-02 (CWE-319): unencrypted transfer permitted, so a client can read PHI over plain
  # HTTP against the blob endpoint.
  enable_https_traffic_only = false

  # INFRA-03 (CWE-326): TLS 1.0 accepted.
  min_tls_version = "TLS1_0"

  # INFRA-04 (CWE-284): no network rules, so the account is reachable from any address on the
  # internet rather than only from the portal's subnet.
  public_network_access_enabled = true

  # INFRA-09 (CWE-404): blob soft-delete off, so a deletion is immediate and unrecoverable -
  # which matters here because the same wide-open access that allows reads allows deletes.
  blob_properties {
    delete_retention_policy {
      days = 0
    }
  }
}

# INFRA-01 (flagship, CWE-284): container access type "container" means anonymous read of both
# the blobs AND the container listing. Anyone who learns the account name can enumerate every
# patient document and download it, with no token, forged or otherwise.
#
# This is the finding the whole fixture is built around, and it is one line.
resource "azurerm_storage_container" "patient_documents" {
  name                  = "patient-documents"
  storage_account_name  = azurerm_storage_account.archive.name
  container_access_type = "container"
}

# INFRA-08 (CWE-532): application logs, including the identifiers CODE-06 writes, land in a
# second container that is also anonymously readable - blob-level rather than container-level,
# so the listing is private but any known path is not.
resource "azurerm_storage_container" "portal_logs" {
  name                  = "portal-logs"
  storage_account_name  = azurerm_storage_account.archive.name
  container_access_type = "blob"
}

# Noise: a container that is correctly private, unused by the application, and holds nothing.
# Present so the fixture can tell "configured correctly" apart from "not configured".
resource "azurerm_storage_container" "staging_unused" {
  name                  = "staging-unused"
  storage_account_name  = azurerm_storage_account.archive.name
  container_access_type = "private"
}
