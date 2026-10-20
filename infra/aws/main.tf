# AWS side of the GitHub pipeline: one EC2 host (Docker + Caddy), ECR, an S3 bundle bucket, a Secrets Manager secret for .env,
# and a GitHub OIDC role. Written without being applied: run `terraform init && terraform validate && terraform plan` first.
# See docs/DEPLOYMENT_AWS.md.
terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

provider "aws" {
  region = var.aws_region
  default_tags { tags = { Project = "sentrail" } }
}

data "aws_caller_identity" "me" {}
data "aws_vpc" "default" { default = true }
data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}
data "aws_ssm_parameter" "ubuntu" {
  name = "/aws/service/canonical/ubuntu/server/22.04/stable/current/amd64/hvm/ebs-gp2/ami-id"
}

locals {
  registry = "${data.aws_caller_identity.me.account_id}.dkr.ecr.${var.aws_region}.amazonaws.com"
  oidc_arn = var.create_github_oidc_provider ? aws_iam_openid_connect_provider.github[0].arn : "arn:aws:iam::${data.aws_caller_identity.me.account_id}:oidc-provider/token.actions.githubusercontent.com"
}

# ---------------- Images ----------------
resource "aws_ecr_repository" "repo" {
  for_each             = toset(["sentrail-api", "sentrail-web"])
  name                 = each.key
  image_tag_mutability = "MUTABLE" # a re-run of the same commit may push its tag again
  image_scanning_configuration { scan_on_push = true }
}

resource "aws_ecr_lifecycle_policy" "repo" {
  for_each   = aws_ecr_repository.repo
  repository = each.value.name
  policy = jsonencode({ rules = [{
    rulePriority = 1
    description  = "keep the last 25 images (rollback targets)"
    selection    = { tagStatus = "any", countType = "imageCountMoreThan", countNumber = 25 }
    action       = { type = "expire" }
  }] })
}

# ---------------- Deploy bundle bucket and .env secret ----------------
resource "aws_s3_bucket" "deploy" {
  bucket = "sentrail-deploy-${data.aws_caller_identity.me.account_id}-${var.aws_region}"
}

resource "aws_s3_bucket_public_access_block" "deploy" {
  bucket                  = aws_s3_bucket.deploy.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "deploy" {
  bucket = aws_s3_bucket.deploy.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "deploy" {
  bucket = aws_s3_bucket.deploy.id
  rule {
    id     = "expire-bundles"
    status = "Enabled"
    filter { prefix = "bundles/" }
    expiration { days = 60 }
  }
}

# The whole production .env is the secret value. Terraform creates the empty secret; you put the value (docs/DEPLOYMENT_AWS.md).
resource "aws_secretsmanager_secret" "env" {
  name                    = "sentrail/prod/env"
  recovery_window_in_days = 7
}

# ---------------- The host ----------------
resource "aws_security_group" "app" {
  name        = "sentrail-app"
  description = "HTTPS and HTTP (certificate issuance) only; administration goes through SSM, not SSH"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description      = "HTTP (redirect and Lets Encrypt)"
    from_port        = 80
    to_port          = 80
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }
  ingress {
    description      = "HTTPS"
    from_port        = 443
    to_port          = 443
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

data "aws_iam_policy_document" "ec2_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "host" {
  name               = "sentrail-host"
  assume_role_policy = data.aws_iam_policy_document.ec2_trust.json
}

resource "aws_iam_role_policy_attachment" "host_ssm" {
  role       = aws_iam_role.host.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

data "aws_iam_policy_document" "host" {
  statement {
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }
  statement {
    actions   = ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer", "ecr:BatchCheckLayerAvailability"]
    resources = [for r in aws_ecr_repository.repo : r.arn]
  }
  statement {
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.deploy.arn}/bundles/*"]
  }
  statement {
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.env.arn]
  }
}

resource "aws_iam_role_policy" "host" {
  name   = "deploy-inputs"
  role   = aws_iam_role.host.id
  policy = data.aws_iam_policy_document.host.json
}

resource "aws_iam_instance_profile" "host" {
  name = "sentrail-host"
  role = aws_iam_role.host.name
}

resource "aws_instance" "app" {
  ami                         = data.aws_ssm_parameter.ubuntu.value
  instance_type               = var.instance_type
  subnet_id                   = data.aws_subnets.default.ids[0]
  vpc_security_group_ids      = [aws_security_group.app.id]
  iam_instance_profile        = aws_iam_instance_profile.host.name
  user_data                   = file("${path.module}/user_data.sh")
  associate_public_ip_address = true
  disable_api_termination     = true # the database lives on this disk

  metadata_options {
    http_tokens                 = "required" # IMDSv2; hop limit 1 keeps containers away from the instance role
    http_put_response_hop_limit = 1
  }

  root_block_device {
    volume_type = "gp3"
    volume_size = var.root_volume_gb
    encrypted   = true
    tags        = { Backup = "daily" }
  }

  tags = { Name = "sentrail-prod" }

  lifecycle {
    ignore_changes = [ami, user_data] # a newer AMI must never replace the host that holds the data
  }
}

resource "aws_eip" "app" {
  instance = aws_instance.app.id
  domain   = "vpc"
}

resource "aws_route53_record" "app" {
  for_each = var.route53_zone_id == "" ? toset([]) : toset(var.hostnames)
  zone_id  = var.route53_zone_id
  name     = each.key
  type     = "A"
  ttl      = 300
  records  = [aws_eip.app.public_ip]
}

# ---------------- Daily disk snapshots (Postgres data and the API's data volume are on the root disk) ----------------
data "aws_iam_policy_document" "dlm_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["dlm.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "dlm" {
  name               = "sentrail-dlm"
  assume_role_policy = data.aws_iam_policy_document.dlm_trust.json
}

resource "aws_iam_role_policy_attachment" "dlm" {
  role       = aws_iam_role.dlm.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSDataLifecycleManagerServiceRole"
}

resource "aws_dlm_lifecycle_policy" "daily" {
  description        = "Daily snapshots of the Sentrail host disk kept 14 days"
  execution_role_arn = aws_iam_role.dlm.arn
  state              = "ENABLED"
  policy_details {
    resource_types = ["VOLUME"]
    target_tags    = { Backup = "daily" }
    schedule {
      name = "daily"
      create_rule {
        interval      = 24
        interval_unit = "HOURS"
        times         = ["21:00"]
      }
      retain_rule { count = 14 }
      copy_tags = true
    }
  }
}

# ---------------- GitHub Actions -> AWS (OIDC, no stored keys) ----------------
resource "aws_iam_openid_connect_provider" "github" {
  count           = var.create_github_oidc_provider ? 1 : 0
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

data "aws_iam_policy_document" "github_trust" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [local.oidc_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition { # the build job runs on main; the deploy job runs in the "production" environment
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${var.github_repo}:ref:refs/heads/main", "repo:${var.github_repo}:environment:production"]
    }
  }
}

resource "aws_iam_role" "github_deploy" {
  name               = "sentrail-github-deploy"
  assume_role_policy = data.aws_iam_policy_document.github_trust.json
}

data "aws_iam_policy_document" "github_deploy" {
  statement {
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }
  statement {
    actions = [
      "ecr:BatchCheckLayerAvailability", "ecr:InitiateLayerUpload", "ecr:UploadLayerPart",
      "ecr:CompleteLayerUpload", "ecr:PutImage", "ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer",
      "ecr:DescribeImages", # rollback target check and the list-versions action
    ]
    resources = [for r in aws_ecr_repository.repo : r.arn]
  }
  statement {
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.deploy.arn}/bundles/*"]
  }
  statement {
    actions = ["ssm:SendCommand"]
    resources = [
      aws_instance.app.arn,
      "arn:aws:ssm:${var.aws_region}::document/AWS-RunShellScript",
    ]
  }
  statement {
    actions   = ["ssm:GetCommandInvocation", "ssm:ListCommandInvocations", "ssm:DescribeInstanceInformation"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "github_deploy" {
  name   = "build-and-deploy"
  role   = aws_iam_role.github_deploy.id
  policy = data.aws_iam_policy_document.github_deploy.json
}
