# List existing outposts, optionally filtered by cloud provider.
data "cortexcloud_outposts" "example" {
  cloud_provider = "AWS"
}

# Output the IDs of all matching outposts.
output "outpost_ids" {
  value = [for o in data.cortexcloud_outposts.example.outposts : o.id]
}
