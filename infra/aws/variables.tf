variable "aws_region" {
  description = "Region for everything (EC2, ECR, S3, Secrets Manager)"
  type        = string
}

variable "github_repo" {
  description = "owner/name of the GitHub repository allowed to deploy"
  type        = string
  default     = "Ansuman0/sentrailfraudanalyst"
}

variable "instance_type" {
  description = "8 GB RAM minimum: the API image carries spaCy and the ML libraries, Keycloak needs about 1 GB"
  type        = string
  default     = "t3.large"
}

variable "root_volume_gb" {
  type    = number
  default = 60
}

variable "hostnames" {
  description = "Public names; all point at the instance's Elastic IP"
  type        = list(string)
  default     = ["sentrail.qatech.world", "api.sentrail.qatech.world", "auth.sentrail.qatech.world"]
}

variable "route53_zone_id" {
  description = "Hosted zone ID of qatech.world if the DNS is in Route 53 (records are then created for you). Empty = create the A records at your DNS provider."
  type        = string
  default     = ""
}

variable "create_github_oidc_provider" {
  description = "Set false if this AWS account already has the token.actions.githubusercontent.com OIDC provider"
  type        = bool
  default     = true
}
