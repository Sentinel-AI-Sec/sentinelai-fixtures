# The gateway itself, the IoT policy the fleet uses, and the queue behind it.

resource "aws_ecs_cluster" "gateway" {
  name = "iot-gateway-cluster"
}

resource "aws_ecs_task_definition" "gateway_task" {
  family                   = "iot-gateway-task"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "512"
  memory                   = "1024"
  execution_role_arn       = aws_iam_role.gateway_task_role.arn
  task_role_arn            = aws_iam_role.gateway_task_role.arn

  container_definitions = jsonencode([
    {
      name = "device-gateway"

      # The code->infra join. Must normalize to the same coordinate as the Dockerfile's
      # LABEL org.sentinelai.image.
      image = "registry.hub.docker.com/iot/device-gateway:4.1.2"

      portMappings = [
        {
          containerPort = 8080
          protocol      = "tcp"
        }
      ]

      # INFRA-05 (CWE-798): the bucket write credential as a plaintext environment variable.
      # This is what CODE-01's XXE reads out of /proc/self/environ - the file-read primitive
      # and the credential's storage location are what make each other useful. Dummy value.
      environment = [
        {
          name  = "Firmware__WriteKey"
          value = "AKIAFIXTUREDUMMYKEY0/wJalrFixtureDummySecret000111"
        }
      ]
    }
  ])
}

resource "aws_ecs_service" "gateway" {
  name            = "device-gateway"
  cluster         = aws_ecs_cluster.gateway.id
  task_definition = aws_ecs_task_definition.gateway_task.arn
  desired_count   = 2
  launch_type     = "FARGATE"

  network_configuration {
    subnets = var.subnet_ids

    # INFRA-06 (CWE-668): public IP, so both CODE-01's XXE and CODE-06's unauthenticated
    # publish endpoint are reachable from the internet.
    assign_public_ip = true
    security_groups  = [aws_security_group.gateway_sg.id]
  }
}

# INFRA-07 (CWE-284): the security group accepts the MQTT port from anywhere, and CODE-04 hands
# devices a plaintext broker endpoint - so fleet telemetry and provisioning keys are readable on
# the wire by anyone on the path.
resource "aws_security_group" "gateway_sg" {
  name        = "iot-gateway-sg"
  description = "Device gateway ingress"
  vpc_id      = var.vpc_id

  ingress {
    description = "http"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "mqtt plaintext"
    from_port   = 1883
    to_port     = 1883
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

# INFRA-08 (CWE-284): the IoT policy every device holds allows iot:* on *. A single recovered
# device certificate - and these ship inside physical hardware anyone can buy - is full control
# of the IoT account.
resource "aws_iot_policy" "fleet" {
  name = "fleet-device-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "iot:*"
        Resource = "*"
      }
    ]
  })
}

# INFRA-09 (CWE-311): the telemetry queue is unencrypted.
resource "aws_sqs_queue" "telemetry" {
  name              = "iot-telemetry"
  kms_master_key_id = ""
}

resource "aws_iam_role" "gateway_task_role" {
  name = "iot-gateway-task-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action    = "sts:AssumeRole"
        Effect    = "Allow"
        Principal = { Service = "ecs-tasks.amazonaws.com" }
      }
    ]
  })
}

# INFRA-10 (CWE-732): the task role can write anywhere in S3, not just the firmware prefix - so
# the credential stolen through INFRA-05 reaches the build-logs bucket too, despite that bucket
# being correctly locked down at the public-access level. A correctly configured resource is
# still reachable if something else holds a wildcard over it.
resource "aws_iam_role_policy" "gateway_s3_policy" {
  name = "iot-gateway-s3-policy"
  role = aws_iam_role.gateway_task_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:PutObject", "s3:GetObject", "s3:DeleteObject"]
        Resource = "*"
      }
    ]
  })
}
