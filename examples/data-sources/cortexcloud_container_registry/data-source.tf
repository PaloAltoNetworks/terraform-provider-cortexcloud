data "cortexcloud_container_registry" "example" {
  id = "conn-1234567890"
}

output "container_registry_name" {
  value = data.cortexcloud_container_registry.example.name
}
