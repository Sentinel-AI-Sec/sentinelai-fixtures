terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

# --- Networking (minimal, fixture-only) ---------------------------------

resource "aws_security_group" "order_svc_sg" {
  name        = "order-svc-sg"
  description = "Security group for the order service (fixture)"

  # VULN (INFRA-05): unrestricted ingress on an application port.
  # Checkov: CKV_AWS_24 / CKV_AWS_260 (open ingress from 0.0.0.0/0)
  ingress {
    description = "app port open to the world"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# --- The flagship ECS/Fargate task --------------------------------------
# This is the node the code->infra image-name join resolves to
# (image "tinyapp/order", matching the Dockerfile after registry/tag strip).

resource "aws_ecs_task_definition" "order_task" {
  family                   = "order-task"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = aws_iam_role.order_task_role.arn
  task_role_arn            = aws_iam_role.order_task_role.arn

  # VULN (INFRA-06): no logConfiguration block at all -> Trivy/Checkov flag
  # missing container logging (observability + forensics gap).
  container_definitions = jsonencode([
    {
      name  = "order-service"
      image = "registry.hub.docker.com/tinyapp/order:1.4.2"
      portMappings = [
        {
          containerPort = 8080
          hostPort      = 8080
        }
      ]
    }
  ])
}

resource "aws_ecs_service" "order_service" {
  name            = "order-service"
  launch_type     = "FARGATE"
  desired_count   = 1
  task_definition = aws_ecs_task_definition.order_task.arn

  network_configuration {
    subnets          = ["subnet-00000000000000000"]
    security_groups  = [aws_security_group.order_svc_sg.id]
    assign_public_ip = true
  }
}

# --- Secondary task: the deliberately AMBIGUOUS image join --------------
# This task's image comes from a variable/registry prefix that will NOT
# normalize to a clean match against any Dockerfile in this fixture.
# Intended outcome: graph_edges.confidence = "unresolved" for this seam.

resource "aws_ecs_task_definition" "legacy_worker_task" {
  family                   = "legacy-worker-task"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = aws_iam_role.legacy_worker_role.arn
  task_role_arn            = aws_iam_role.legacy_worker_role.arn

  container_definitions = jsonencode([
    {
      name  = "legacy-worker"
      image = var.legacy_worker_image
    }
  ])
}
