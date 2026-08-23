# The payments service: an ECS Fargate task behind an ALB, with a Postgres ledger.
#
# The image coordinate below is the code->infra join. It must normalize to the same value as the
# Dockerfile's LABEL org.sentinelai.image, or the chain from CODE-01 to INFRA-01 cannot be
# reconstructed and the whole fixture proves nothing.

provider "aws" {
  region = var.region
}

resource "aws_ecs_cluster" "payments" {
  name = "payments-cluster"

  # INFRA-04 (CWE-778): Container Insights off, so there is no execution telemetry to
  # investigate with after the fact.
  setting {
    name  = "containerInsights"
    value = "disabled"
  }
}

resource "aws_ecs_task_definition" "payments_task" {
  family                   = "payments-task"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "512"
  memory                   = "1024"
  execution_role_arn       = aws_iam_role.payments_task_role.arn
  task_role_arn            = aws_iam_role.payments_task_role.arn

  container_definitions = jsonencode([
    {
      name  = "payments-api"
      image = "registry.hub.docker.com/fintech/payments:2.1.0"

      portMappings = [
        {
          containerPort = 8080
          protocol      = "tcp"
        }
      ]

      # INFRA-05 (CWE-798): the database password is passed as a plaintext environment
      # variable, so it is visible in the task definition, in the console, and to anyone who
      # can call ecs:DescribeTaskDefinition. Dummy fixture value.
      environment = [
        {
          name  = "ConnectionStrings__Ledger"
          value = "Server=ledger.internal;Database=payments;User Id=svc_payments;Password=P@ymentsFixture123;Encrypt=false"
        }
      ]
    }
  ])
}

resource "aws_ecs_service" "payments" {
  name            = "payments"
  cluster         = aws_ecs_cluster.payments.id
  task_definition = aws_ecs_task_definition.payments_task.arn
  desired_count   = 2
  launch_type     = "FARGATE"

  network_configuration {
    subnets = var.subnet_ids

    # INFRA-06 (CWE-668): the task gets a public IP, so the SSRF in CODE-01 is reachable from
    # the internet rather than only from inside the VPC.
    assign_public_ip = true
    security_groups  = [aws_security_group.payments_sg.id]
  }
}

# INFRA-07 (CWE-284): the security group accepts traffic from anywhere on both the app port and
# the database port. The second rule is the one that matters - it means the ledger is reachable
# directly, not only through the application.
resource "aws_security_group" "payments_sg" {
  name        = "payments-sg"
  description = "Payments service ingress"
  vpc_id      = var.vpc_id

  ingress {
    description = "app"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "postgres"
    from_port   = 5432
    to_port     = 5432
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

# INFRA-08 (CWE-319): the load balancer listens on plain HTTP, so card-adjacent traffic and the
# session cookie cross the internet in the clear.
resource "aws_lb" "payments" {
  name               = "payments-alb"
  internal           = false
  load_balancer_type = "application"
  subnets            = var.subnet_ids

  # INFRA-09 (CWE-778): access logging disabled.
  access_logs {
    bucket  = ""
    enabled = false
  }
}

resource "aws_lb_listener" "payments_http" {
  load_balancer_arn = aws_lb.payments.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "forward"
    forward {
      target_group {
        arn = aws_lb_target_group.payments.arn
      }
    }
  }
}

resource "aws_lb_target_group" "payments" {
  name        = "payments-tg"
  port        = 8080
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = var.vpc_id
}
