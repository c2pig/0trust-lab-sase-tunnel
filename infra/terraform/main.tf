provider "cloudflare" {}

provider "google" {
  project = var.gcp_project_id
  region  = var.gcp_region
}

# Static SPA hosting only (dist/); API traffic is routed by 0trust-lab-router to Cloud Run.
module "sase_tunnel_lab" {
  source = "git::https://github.com/c2pig/managed-infrastructure.git//modules/cloudflare-pages-lab?ref=v1.0.0"

  cloudflare_account_id = var.cloudflare_account_id
  cloudflare_zone_id    = var.cloudflare_zone_id
  state_kv_namespace_id = var.state_kv_namespace_id
  pages_project_name    = "0trust-lab-sase-tunnel"
  enable_custom_domain  = false

  plain_env_vars = {
    ENVIRONMENT = var.environment
  }

  secret_env_vars = {}
}

# Cloud Run API backend + Firestore Native state (min_instance_count = 0, $0 idle cost).
module "cloud_run_lab" {
  source = "git::https://github.com/c2pig/managed-infrastructure.git//modules/cloud-run-lab?ref=v1.0.0"

  gcp_project_id                 = var.gcp_project_id
  gcp_region                     = var.gcp_region
  lab_slug                       = "sase-tunnel"
  image                          = var.cloud_run_image
  environment                    = var.environment
  firestore_collection           = var.firestore_collection
  lab_router_secret_id           = var.lab_router_secret_id
  deployer_service_account_email = var.deployer_service_account_email

  plain_env_vars = merge(
    {
      SASE_INTEGRATION_MODE = var.sase_integration_mode
    },
    var.otlp_endpoint != "" ? { OTLP_ENDPOINT = var.otlp_endpoint } : {},
    var.cf_access_team_domain != "" ? { CF_ACCESS_TEAM_DOMAIN = var.cf_access_team_domain } : {},
    var.enable_cloudflare_zero_trust || var.cf_tunnel_id != "" ? {
      CF_ACCOUNT_ID = var.cloudflare_account_id
      CF_TUNNEL_ID  = var.enable_cloudflare_zero_trust ? cloudflare_zero_trust_tunnel_cloudflared.sandbox[0].id : var.cf_tunnel_id
    } : {},
    var.enable_cloudflare_zero_trust || var.cf_access_aud != "" ? {
      CF_ACCESS_AUD = var.enable_cloudflare_zero_trust ? cloudflare_zero_trust_access_application.sandbox_erp[0].aud : var.cf_access_aud
    } : {},
    var.origin_direct_probe_url != "" ? { ORIGIN_DIRECT_PROBE_URL = var.origin_direct_probe_url } : {}
  )

  secret_env_vars = merge(
    var.otlp_auth_header_secret_id != "" ? { OTLP_AUTH_HEADER = var.otlp_auth_header_secret_id } : {},
    var.cf_api_token_secret_id != "" ? { CF_API_TOKEN = var.cf_api_token_secret_id } : {}
  )
}

# Optional Phase 2: Dedicated sandbox cloudflared tunnel & Cloudflare Access app (gated by enable_cloudflare_zero_trust).
resource "cloudflare_zero_trust_tunnel_cloudflared" "sandbox" {
  count = var.enable_cloudflare_zero_trust ? 1 : 0

  account_id = var.cloudflare_account_id
  name       = "0trust-lab5-sase-sandbox"
  config_src = "cloudflare"
}

resource "cloudflare_zero_trust_access_application" "sandbox_erp" {
  count = var.enable_cloudflare_zero_trust ? 1 : 0

  account_id       = var.cloudflare_account_id
  name             = "0trust Lab 5 SASE Sandbox ERP"
  domain           = "sase-sandbox.0trust.dev"
  type             = "self_hosted"
  session_duration = "1h"
}

