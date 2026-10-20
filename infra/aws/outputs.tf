output "elastic_ip" {
  description = "Point the three A records here (unless Route 53 did it)"
  value       = aws_eip.app.public_ip
}

output "github_variables" {
  description = "GitHub -> Settings -> Secrets and variables -> Actions -> Variables (repository variables, none are secret). Also add API_URL and APP_URL."
  value = {
    AWS_REGION          = var.aws_region
    AWS_DEPLOY_ROLE_ARN = aws_iam_role.github_deploy.arn
    EC2_INSTANCE_ID     = aws_instance.app.id
    ECR_REGISTRY        = "${data.aws_caller_identity.me.account_id}.dkr.ecr.${var.aws_region}.amazonaws.com"
    DEPLOY_BUCKET       = aws_s3_bucket.deploy.bucket
    SECRET_ID           = aws_secretsmanager_secret.env.name
  }
}
