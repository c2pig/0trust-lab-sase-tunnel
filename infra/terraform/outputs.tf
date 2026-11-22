output "pages_project_name" {
  description = "Cloudflare Pages project name."
  value       = module.sase_tunnel_lab.pages_project_name
}

output "pages_subdomain" {
  description = "Default Cloudflare Pages subdomain."
  value       = module.sase_tunnel_lab.pages_subdomain
}

output "lab_url" {
  description = "Production standalone lab URL."
  value       = module.sase_tunnel_lab.lab_url
}
