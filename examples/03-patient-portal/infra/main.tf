# The portal itself: a Linux container app, its database, and the vault it does not use.

resource "azurerm_container_group" "portal" {
  name                = "patient-portal"
  location            = azurerm_resource_group.portal.location
  resource_group_name = azurerm_resource_group.portal.name
  os_type             = "Linux"

  # INFRA-05 (CWE-319): the container group is exposed publicly on port 80. PHI in the clear,
  # straight off the internet.
  ip_address_type = "Public"

  container {
    name = "patient-portal"

    # The code->infra join. Must normalize to the same coordinate as the Dockerfile's
    # LABEL org.sentinelai.image, or the chain from CODE-01 to INFRA-01 cannot be rebuilt.
    image = "registry.hub.docker.com/health/patient-portal:1.9.0"

    cpu    = "1"
    memory = "2"

    ports {
      port     = 80
      protocol = "TCP"
    }

    # INFRA-06 (CWE-798): the storage account key as a plain environment variable, so it is
    # readable from the Azure portal, the CLI, and any principal with reader on the group.
    # Dummy fixture value.
    environment_variables = {
      "ConnectionStrings__Archive" = "DefaultEndpointsProtocol=https;AccountName=phiportalarchive;AccountKey=Zm...FIXTURE...DUMMY...KEY...000111==;EndpointSuffix=core.windows.net"
    }
  }

  # INFRA-10 (CWE-778): no diagnostic settings, so container stdout is not retained anywhere an
  # investigator could read it.
  diagnostics {
    log_analytics {
      workspace_id  = ""
      workspace_key = ""
    }
  }
}

resource "azurerm_mssql_server" "records" {
  name                         = "sql-patient-records"
  resource_group_name          = azurerm_resource_group.portal.name
  location                     = azurerm_resource_group.portal.location
  version                      = "12.0"
  administrator_login          = "portaladmin"

  # Dummy fixture value.
  administrator_login_password = "P0rtalFixture!123"

  # INFRA-07 (CWE-284): the SQL server accepts connections from the public internet.
  public_network_access_enabled = true

  # INFRA-11 (CWE-311): TLS floor left at 1.0.
  minimum_tls_version = "1.0"
}

# INFRA-12 (CWE-284): a firewall rule spanning the entire IPv4 range. The classic
# "AllowAllWindowsAzureIps" mistake taken to its conclusion.
resource "azurerm_mssql_firewall_rule" "allow_all" {
  name             = "allow-all"
  server_id        = azurerm_mssql_server.records.id
  start_ip_address = "0.0.0.0"
  end_ip_address   = "255.255.255.255"
}

# INFRA-13 (CWE-311): the vault exists, is soft-delete disabled and purge-protection off, and
# the application never uses it - the key it should hold is in INFRA-06's environment variable
# instead. A correctly-provisioned control that nothing is wired to.
resource "azurerm_key_vault" "portal" {
  name                        = "kv-patient-portal"
  location                    = azurerm_resource_group.portal.location
  resource_group_name         = azurerm_resource_group.portal.name
  tenant_id                   = var.tenant_id
  sku_name                    = "standard"
  soft_delete_retention_days  = 7
  purge_protection_enabled    = false
  enable_rbac_authorization   = false
}
