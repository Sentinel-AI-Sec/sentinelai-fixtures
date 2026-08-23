variable "region" {
  description = "AWS region for the payments stack"
  type        = string
  default     = "eu-west-1"
}

variable "vpc_id" {
  description = "VPC the service runs in"
  type        = string
  default     = "vpc-0fixture000000000"
}

variable "subnet_ids" {
  description = "Subnets for the service and load balancer"
  type        = list(string)
  default     = ["subnet-0fixture0000000a", "subnet-0fixture0000000b"]
}
