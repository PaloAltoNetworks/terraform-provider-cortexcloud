// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"context"
	"testing"
)

func BenchmarkGenerateRequestID(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = generateRequestID()
	}
}

func BenchmarkGetOrGenerateRequestID(b *testing.B) {
	ctx := context.Background()

	b.Run("with existing ID", func(b *testing.B) {
		ctx = WithRequestID(ctx, "req_existing")
		for i := 0; i < b.N; i++ {
			_, _ = GetOrGenerateRequestID(ctx)
		}
	})

	b.Run("without existing ID", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = GetOrGenerateRequestID(context.Background())
		}
	})
}

func BenchmarkWithRequestID(b *testing.B) {
	ctx := context.Background()
	for i := 0; i < b.N; i++ {
		_ = WithRequestID(ctx, "req_test123")
	}
}

func BenchmarkGetRequestID(b *testing.B) {
	ctx := WithRequestID(context.Background(), "req_test123")
	for i := 0; i < b.N; i++ {
		_ = GetRequestID(ctx)
	}
}
