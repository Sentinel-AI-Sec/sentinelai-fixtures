variable "region" {
  description = "AWS region for the gateway"
  type        = string
  default     = "eu-central-1"
}

variable "vpc_id" {
  description = "VPC the gateway runs in"
  type        = string
  default     = "vpc-0fixture000000000"
}

variable "subnet_ids" {
  description = "Subnets for the gateway service"
  type        = list(string)
  default     = ["subnet-0fixture0000000c", "subnet-0fixture0000000d"]
}
