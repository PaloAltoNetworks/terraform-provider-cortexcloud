# Onboard a Docker Hub registry connector, scanning via a Cortex-managed
# cloud environment.
resource "cortexcloud_container_registry" "dockerhub" {
  vendor = "DOCKER_HUB"
  name   = "dockerhub-connector"
  url    = "https://registry-1.docker.io"

  username = "svc-account"
  password = var.dockerhub_password

  scanning_mode  = "CLOUD"
  cloud_provider = "AWS"
  region         = "us-east-1"

  initial_scan_configuration = {
    mode     = "TAGS_MODIFIED_DAYS"
    num_days = 30
  }

  docker_hub = {
    repository = "my-org/my-repo"
  }
}

# Onboard a self-hosted Harbor registry, scanning via an Outpost.
resource "cortexcloud_container_registry" "harbor" {
  vendor = "HARBOR"
  name   = "harbor-connector"
  url    = "https://harbor.internal.example.com"

  auth_token = var.harbor_token

  scanning_mode = "OUTPOST"
  outpost_id    = "outpost-1234"

  initial_scan_configuration = {
    mode = "ALL"
  }

  insecure_pull  = false
  ca_certificate = var.harbor_ca_certificate
}

# Scope scanning to a subset of assets using asset_scope_filters.
resource "cortexcloud_container_registry" "gitlab" {
  vendor = "GITLAB_CONTAINER_REGISTRY"
  name   = "gitlab-connector"
  url    = "https://gitlab.example.com"

  auth_token = var.gitlab_token

  scanning_mode  = "CLOUD"
  cloud_provider = "GCP"
  region         = "us-central1"

  initial_scan_configuration = {
    mode = "LATEST_TAG"
  }

  gitlab = {
    group_ids = "123,456"
  }

  filter_type = "EXCLUDE"
  asset_scope_filters = {
    or = [
      {
        search_field = "Registry"
        search_type  = "EQ"
        search_value = "archived/legacy-repo"
      }
    ]
  }
}
