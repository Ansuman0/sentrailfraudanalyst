variable "project_id" {
  description = "GCP project that holds everything"
  type        = string
}

variable "region" {
  type    = string
  default = "us-central1"
}

variable "zone" {
  type    = string
  default = "us-central1-a"
}

variable "github_repo" {
  description = "owner/name of the GitHub repository allowed to deploy"
  type        = string
  default     = "Ansuman0/sentrailfraudanalyst"
}

variable "machine_type" {
  description = "8 GB RAM minimum: the API image carries spaCy and the ML libraries, Keycloak needs about 1 GB. e2-standard-2 = 2 vCPU, 8 GB"
  type        = string
  default     = "e2-standard-2"
}

variable "boot_disk_gb" {
  type    = number
  default = 30
}

variable "hostnames" {
  description = "Public names; all point at the VM's static IP"
  type        = list(string)
  default     = ["sentrail.qatech.world", "api.sentrail.qatech.world", "auth.sentrail.qatech.world"]
}

variable "dns_zone_name" {
  description = "Cloud DNS managed zone for qatech.world. Empty = create no records (add the A records at your registrar)"
  type        = string
  default     = ""
}
