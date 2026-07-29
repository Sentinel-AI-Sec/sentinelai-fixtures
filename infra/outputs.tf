output "order_task_role_arn" {
  value = aws_iam_role.order_task_role.arn
}

output "customer_data_bucket" {
  value = aws_s3_bucket.customer_data.bucket
}

output "order_ecs_service" {
  value = aws_ecs_service.order_service.name
}
