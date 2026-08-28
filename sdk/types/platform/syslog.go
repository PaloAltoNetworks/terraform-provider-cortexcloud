// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package types

type SyslogIntegration struct {
	ID              int     `json:"SYSLOG_INTEGRATION_ID"`
	Name            string  `json:"SYSLOG_INTEGRATION_NAME"`
	Address         string  `json:"SYSLOG_INTEGRATION_ADDRESS"`
	Port            int     `json:"SYSLOG_INTEGRATION_PORT"`
	Protocol        string  `json:"SYSLOG_INTEGRATION_PROTOCOL"`
	Facility        string  `json:"FACILITY"`
	Status          string  `json:"SYSLOG_INTEGRATION_STATUS"`
	Error           *string `json:"SYSLOG_INTEGRATION_ERROR"`
	CertificateName *string `json:"SYSLOG_INTEGRATION_CERTIFICATE_NAME"`
}

type CreateSyslogIntegrationRequest struct {
	Name         string `json:"name"`
	Address      string `json:"address"`
	Port         int    `json:"port"`
	Protocol     string `json:"protocol"`
	Facility     string `json:"facility"`
	SecurityInfo string `json:"security_info,omitempty"`
}

type SyslogIntegrationSecurityInfo struct {
	CertificateName         string `json:"certificate_name"`
	IgnoreCertificateErrors string `json:"ignore_cert_errors"`
	CertificateContent      string `json:"certificate_content"`
}

type CreateSyslogIntegrationResponse struct {
	IntegrationID int    `json:"syslog_integration_id"`
	Name          string `json:"name"`
}

type ListSyslogIntegrationsRequest struct {
	Filters []ListSyslogIntegrationsFilter `json:"filters"`
}

type ListSyslogIntegrationsFilter interface {
	IsSyslogIntegrationsFilter()
}

type ListSyslogIntegrationsFilterString struct {
	Field    string `json:"field"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
}

func (f *ListSyslogIntegrationsFilterString) IsSyslogIntegrationsFilter() {}

type ListSyslogIntegrationsFilterInteger struct {
	Field    string `json:"field"`
	Operator string `json:"operator"`
	Value    int    `json:"value"`
}

func (f *ListSyslogIntegrationsFilterInteger) IsSyslogIntegrationsFilter() {}

type ListSyslogIntegrationsResponse struct {
	Count        int                 `json:"objects_count"`
	Integrations []SyslogIntegration `json:"objects"`
}
