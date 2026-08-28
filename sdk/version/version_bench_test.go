// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package version

import "testing"

func BenchmarkUserAgent(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = UserAgent("platform")
	}
}

func BenchmarkUserAgentWithCustom(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = UserAgentWithCustom("platform", "custom/1.0")
	}
}

func BenchmarkInfo(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = Info()
	}
}
