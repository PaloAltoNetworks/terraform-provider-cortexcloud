# AppSec policy for critical findings
resource "cortexcloud_appsec_policy" "critical_findings" {
  name        = "Critical Findings on Production"
  description = "Alert on critical security issues"
  status      = "enabled"

  # Conditions as JSON (supports up to 10 levels of nesting)
  # Each condition clause must include a Finding Type field.
  # Valid Finding Type values: VULNERABILITY, SECRETS, etc.
  conditions = jsonencode({
    AND = [
      {
        SEARCH_FIELD = "Finding Type"
        SEARCH_TYPE  = "EQ"
        SEARCH_VALUE = "VULNERABILITY"
      }
    ]
  })

  # Each trigger block must be present on CREATE/UPDATE — the API rejects
  # requests that omit any of periodic / pr / cicd / ci_image / image_registry
  # with HTTP 422 ValidateError.
  periodic_trigger = {
    enabled = true
    actions = {
      report_issue = true
    }
  }

  pr_trigger = {
    enabled = true
    actions = {
      report_issue      = true
      report_pr_comment = true
      block_pr          = false
    }
  }

  cicd_trigger = {
    enabled = false
    actions = {
      report_issue = false
      block_cicd   = false
      report_cicd  = false
    }
  }

  ci_image_trigger = {
    enabled = false
    actions = {
      report_issue = false
      report_cicd  = false
      block_cicd   = false
    }
  }

  image_registry_trigger = {
    enabled = false
    actions = {
      report_issue = false
    }
  }

  asset_group_ids = [1]
}
