variable "location" {
  description = "Azure region for the portal"
  type        = string
  default     = "uksouth"
}

variable "tenant_id" {
  description = "Entra tenant the vault belongs to"
  type        = string
  default     = "00000000-0000-0000-0000-000000000fix"
}
