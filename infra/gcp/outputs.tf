output "static_ip" {
  description = "Point the three A records here"
  value       = google_compute_address.app.address
}

output "github_variables" {
  description = "Repository variables for GitHub (Settings -> Secrets and variables -> Actions -> Variables). None are secret."
  value = {
    GCP_PROJECT      = var.project_id
    GCP_REGION       = var.region
    GCP_ZONE         = var.zone
    GCP_VM           = google_compute_instance.app.name
    GCP_REGISTRY     = local.registry
    GCP_SECRET_ID    = google_secret_manager_secret.env.secret_id
    GCP_DEPLOY_SA    = google_service_account.deploy.email
    GCP_WIF_PROVIDER = google_iam_workload_identity_pool_provider.github.name
  }
}
