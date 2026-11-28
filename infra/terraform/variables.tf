variable "cloudflare_account_id" {
  type        = string
  description = "Cloudflare Account ID."
}

variable "cloudflare_zone_id" {
  type        = string
  description = "Cloudflare Zone ID for 0trust.dev."
}

variable "state_kv_namespace_id" {
  type        = string
  default     = ""
  description = "Legacy STATE_KV namespace ID (retained optional for CF Pages module compatibility; API state is stored in Firestore Native)."
}

variable "gcp_project_id" {
  type        = string
  description = "GCP Project ID hosting the shared Firestore Native DB, Artifact Registry, and Cloud Run services."
}

variable "gcp_region" {
  type        = string
  default     = "us-central1"
  description = "GCP region for Cloud Run service deployment."
}

variable "cloud_run_image" {
  type        = string
  description = "Container image URI in Artifact Registry (e.g. us-central1-docker.pkg.dev/<project>/zerotrust-labs/sase-tunnel:latest)."
}

variable "firestore_collection" {
  type        = string
  default     = "kv_state"
  description = "Firestore Native collection name for KV state documents."
}

variable "lab_router_secret_id" {
  type        = string
  default     = "lab-router-secret"
  description = "GCP Secret Manager secret ID for X-Lab-Router-Secret validation."
}

variable "deployer_service_account_email" {
  type        = string
  default     = ""
  description = "Optional GitHub Actions WIF deployer SA email granted scoped roles/iam.serviceAccountUser on the Lab 5 runtime SA."
}

variable "environment" {
  type        = string
  default     = "production"
  description = "Deployment environment label."
}

variable "otlp_endpoint" {
  type        = string
  default     = ""
  description = "Optional OpenTelemetry OTLP HTTP collector endpoint."
}

variable "otlp_auth_header_secret_id" {
  type        = string
  default     = ""
  description = "Optional GCP Secret Manager secret ID for OTLP_AUTH_HEADER (e.g. grafana-otlp-auth-header)."
}

variable "sase_integration_mode" {
  type        = string
  default     = "auto"
  description = "Lab 5 third-party integration mode: auto (live Cloudflare DoH + CF One when configured), live, or sandbox."
}

variable "enable_cloudflare_zero_trust" {
  type        = bool
  default     = false
  description = "When true, provisions a dedicated sandbox cloudflared tunnel and Cloudflare Access application in Cloudflare Zero Trust."
}

variable "cf_access_team_domain" {
  type        = string
  default     = ""
  description = "Existing Cloudflare Zero Trust team domain (e.g. <team>.cloudflareaccess.com)."
}

variable "cf_access_aud" {
  type        = string
  default     = ""
  description = "Optional Cloudflare Access Application AUD tag (auto-wired when enable_cloudflare_zero_trust = true)."
}

variable "cf_tunnel_id" {
  type        = string
  default     = ""
  description = "Optional existing cloudflared Tunnel ID (auto-wired when enable_cloudflare_zero_trust = true)."
}

variable "cf_api_token_secret_id" {
  type        = string
  default     = ""
  description = "Optional GCP Secret Manager secret ID for CF_API_TOKEN (e.g. cf-api-token)."
}

variable "origin_direct_probe_url" {
  type        = string
  default     = ""
  description = "Optional URL for live direct-to-origin ingress probe (Trap 5B)."
}

