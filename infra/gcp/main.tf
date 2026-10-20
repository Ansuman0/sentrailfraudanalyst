# Sentrail on Google Cloud: one Compute Engine VM (Docker Compose), Artifact Registry, Secret Manager, IAP-only SSH,
# and GitHub Actions deploying through Workload Identity Federation (no keys). Mirrors infra/aws. See docs/DEPLOYMENT_GCP.md.
terraform {
  required_version = ">= 1.5"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
  zone    = var.zone
}

locals {
  registry = "${var.region}-docker.pkg.dev/${var.project_id}/sentrail"
}

resource "google_project_service" "apis" {
  for_each = toset([
    "compute.googleapis.com", "artifactregistry.googleapis.com", "secretmanager.googleapis.com", "iam.googleapis.com",
    "iamcredentials.googleapis.com", "sts.googleapis.com", "iap.googleapis.com", "cloudresourcemanager.googleapis.com",
    "dns.googleapis.com", "oslogin.googleapis.com",
  ])
  service            = each.key
  disable_on_destroy = false
}

# ---- images -----------------------------------------------------------------
resource "google_artifact_registry_repository" "sentrail" {
  repository_id = "sentrail"
  location      = var.region
  format        = "DOCKER"
  description   = "sentrail-api and sentrail-web images; the tag is the commit SHA"
  cleanup_policies {
    id     = "keep-last-30"
    action = "KEEP"
    most_recent_versions { keep_count = 30 }
  }
  depends_on = [google_project_service.apis]
}

# ---- production .env (filled by you, never by Terraform) --------------------
resource "google_secret_manager_secret" "env" {
  secret_id = "sentrail-prod-env"
  replication {
    auto {}
  }
  depends_on = [google_project_service.apis]
}

# ---- the VM -----------------------------------------------------------------
resource "google_service_account" "vm" {
  account_id   = "sentrail-vm"
  display_name = "Sentrail host: pulls images, reads the .env secret"
  depends_on   = [google_project_service.apis]
}

resource "google_artifact_registry_repository_iam_member" "vm_pull" {
  repository = google_artifact_registry_repository.sentrail.name
  location   = var.region
  role       = "roles/artifactregistry.reader"
  member     = "serviceAccount:${google_service_account.vm.email}"
}

resource "google_secret_manager_secret_iam_member" "vm_env" {
  secret_id = google_secret_manager_secret.env.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.vm.email}"
}

resource "google_project_iam_member" "vm_logs" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.vm.email}"
}

resource "google_compute_address" "app" {
  name       = "sentrail-ip"
  region     = var.region
  depends_on = [google_project_service.apis]
}

resource "google_compute_firewall" "web" {
  name          = "sentrail-web"
  network       = "default"
  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["sentrail"]
  allow {
    protocol = "tcp"
    ports    = ["80", "443"]
  }
  depends_on = [google_project_service.apis]
}

resource "google_compute_firewall" "iap_ssh" { # SSH only through Identity-Aware Proxy, never from the internet
  name          = "sentrail-iap-ssh"
  network       = "default"
  source_ranges = ["35.235.240.0/20"]
  target_tags   = ["sentrail"]
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
  depends_on = [google_project_service.apis]
}

resource "google_compute_instance" "app" {
  name                      = "sentrail"
  machine_type              = var.machine_type
  tags                      = ["sentrail"]
  deletion_protection       = true # the database lives on this disk
  allow_stopping_for_update = true

  boot_disk {
    auto_delete = false
    initialize_params {
      image = "ubuntu-os-cloud/ubuntu-2204-lts"
      size  = var.boot_disk_gb
      type  = "pd-balanced"
    }
  }
  network_interface {
    network = "default"
    access_config { nat_ip = google_compute_address.app.address }
  }
  service_account {
    email  = google_service_account.vm.email
    scopes = ["cloud-platform"]
  }
  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }
  metadata = {
    enable-oslogin         = "TRUE"
    block-project-ssh-keys = "TRUE"
  }
  metadata_startup_script = file("${path.module}/user_data.sh")
  depends_on              = [google_project_service.apis]
}

resource "google_compute_resource_policy" "daily" {
  name   = "sentrail-daily-snapshots"
  region = var.region
  snapshot_schedule_policy {
    schedule {
      daily_schedule {
        days_in_cycle = 1
        start_time    = "03:00"
      }
    }
    retention_policy {
      max_retention_days    = 14
      on_source_disk_delete = "KEEP_AUTO_SNAPSHOTS"
    }
  }
}

resource "google_compute_disk_resource_policy_attachment" "daily" {
  name = google_compute_resource_policy.daily.name
  disk = google_compute_instance.app.name # the boot disk is named after the instance
  zone = var.zone
}

# ---- DNS (optional) ---------------------------------------------------------
resource "google_dns_record_set" "app" {
  for_each     = var.dns_zone_name == "" ? toset([]) : toset(var.hostnames)
  managed_zone = var.dns_zone_name
  name         = "${each.key}."
  type         = "A"
  ttl          = 300
  rrdatas      = [google_compute_address.app.address]
}

# ---- GitHub Actions: Workload Identity Federation, no keys -------------------
resource "google_service_account" "deploy" {
  account_id   = "sentrail-deploy"
  display_name = "GitHub Actions deployer"
  depends_on   = [google_project_service.apis]
}

resource "google_iam_workload_identity_pool" "github" {
  workload_identity_pool_id = "sentrail-github"
  depends_on                = [google_project_service.apis]
}

resource "google_iam_workload_identity_pool_provider" "github" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.github.workload_identity_pool_id
  workload_identity_pool_provider_id = "github"
  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.repository" = "assertion.repository"
    "attribute.ref"        = "assertion.ref"
  }
  attribute_condition = "assertion.repository == \"${var.github_repo}\" && assertion.ref == \"refs/heads/main\"" # only main of this repo
  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}

resource "google_service_account_iam_member" "deploy_wif" {
  service_account_id = google_service_account.deploy.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github.name}/attribute.repository/${var.github_repo}"
}

resource "google_artifact_registry_repository_iam_member" "deploy_push" {
  repository = google_artifact_registry_repository.sentrail.name
  location   = var.region
  role       = "roles/artifactregistry.writer"
  member     = "serviceAccount:${google_service_account.deploy.email}"
}

resource "google_compute_instance_iam_member" "deploy_ssh" { # OS Login as admin on this one VM only (the deploy script uses sudo)
  instance_name = google_compute_instance.app.name
  zone          = var.zone
  role          = "roles/compute.osAdminLogin"
  member        = "serviceAccount:${google_service_account.deploy.email}"
}

resource "google_compute_instance_iam_member" "deploy_view" { # lets gcloud look the VM up for scp/ssh
  instance_name = google_compute_instance.app.name
  zone          = var.zone
  role          = "roles/compute.viewer"
  member        = "serviceAccount:${google_service_account.deploy.email}"
}

resource "google_project_iam_member" "deploy_iap" {
  project = var.project_id
  role    = "roles/iap.tunnelResourceAccessor"
  member  = "serviceAccount:${google_service_account.deploy.email}"
}

resource "google_service_account_iam_member" "deploy_act_as_vm" { # needed to SSH to a VM that runs as the VM service account
  service_account_id = google_service_account.vm.name
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${google_service_account.deploy.email}"
}
