variable "region" {
  description = "AWS region for the fixture"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "demo"
}

# NOTE (fixture): this is intentionally resolved from a variable rather than
# a literal, and does NOT exactly match the Dockerfile's image reference
# after normalization (registry prefix differs). This is the deliberate
# "unresolved" cross-layer join used to exercise the confidence-tier logic
# (SEC-19 / graph_edges.confidence = unresolved).
variable "legacy_worker_image" {
  description = "Image reference for the legacy worker task (ambiguous join, intentionally)"
  type        = string
  default     = "registry.internal.example.com/tinyapp-worker:latest"
}
