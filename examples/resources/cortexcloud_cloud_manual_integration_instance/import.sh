# A manually onboarded connector is imported using its connector ID, which is
# the identifier shown for the connector in the Cortex Cloud console.
terraform import cortexcloud_cloud_manual_integration_instance.example <connector_id>

# IMPORTANT: the first "terraform plan" after this import is NOT empty.
#
# Cortex Cloud reports the cloud-side identities in a different shape from the
# one it accepts, and it never reports cloudtrail_role, sqs_url or
# subscription_id at all. Terraform therefore cannot reconstruct the
# "manual_details" you originally supplied, and records what the platform does
# report under the separate, read-only "reported_manual_details" attribute.
#
# So after importing you must declare "manual_details" yourself. Use
# "reported_manual_details" from the imported state as your starting point:
#
#     terraform state show cortexcloud_cloud_manual_integration_instance.example
#
# and add back the members the platform does not report.
#
# Review that first plan carefully before applying it. It is an update, and it
# sends the "manual_details" your configuration declares -- so a value that
# disagrees with the connector's real configuration will be written to the
# connector.
