// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

// Package pagination provides reusable accumulation helpers for Terraform
// provider data sources and resources that need to walk multi-page list
// responses from the Cortex Cloud APIs. It is intentionally agnostic about
// pagination shape (offset/limit, page number, cursor) and about whether the
// caller is a data source or a resource.
//
// The package exposes two layers:
//
//  1. [AccumulateAll] is the low-level loop. The caller supplies a
//     [PageFetcher] closure that owns its own pagination bookkeeping. Use
//     this when the API uses cursor pagination, page-number pagination, or
//     any other shape that does not map cleanly onto search_from/search_to.
//
//  2. [OffsetAccumulateAll] is a thin wrapper around [AccumulateAll] for the
//     common offset/limit case. The caller only has to supply a closure that
//     fetches a single page given a 0-based searchFrom and an inclusive
//     searchTo bound; the offset arithmetic is handled internally.
//
// Both layers honour the same max_results semantics (see [ResolveMaxResults])
// and surface the same [MaxResultsExceededError] when the API reports a
// matching set larger than the cap, so a caller upgrading from one layer to
// the other does not have to change its error-handling code.
package pagination

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/types"
)

// defaultMaxResults is the runtime default applied by [ResolveMaxResults]
// when a max_results framework value is null or unknown. Datasource (and many
// resource) schemas in the terraform-plugin-framework cannot declare Default
// values, so callers apply this default in their Read path.
const defaultMaxResults = 1000

// MaxResultsExceededError is returned by [AccumulateAll] (and therefore
// [OffsetAccumulateAll]) when the API reports more matching records than
// max_results allows. Callers can use [errors.As] to recover the structured
// fields if they want to render a custom diagnostic.
type MaxResultsExceededError struct {
	// TotalCount is the matching record count reported by the API.
	TotalCount int
	// MaxResults is the provided cap value.
	MaxResults int
	// ResourceLabel is the plural noun the caller supplied for the resource
	// being listed (e.g. "standards", "users"), used in the default Error()
	// message.
	ResourceLabel string
}

func (e *MaxResultsExceededError) Error() string {
	return fmt.Sprintf(
		"cortex cloud returned %d %s matching the configured filters, "+
			"which exceeds the max_results cap of %d; "+
			"either narrow the filter, raise max_results, or set max_results = 0 to disable the cap",
		e.TotalCount, e.ResourceLabel, e.MaxResults,
	)
}

// Resolves the integer value of the provided Int64 framework type as expected by
// the accumulation helpers:
//   - null or unknown   --> int(1000) - package default
//   - explicit 0        --> int(0)  - disables results cap
//   - any other value n --> int(n)
//
// Always invoke before calling `AccumulateAll` or `OffsetAccumulateAll`, as
// framework types do not always support a declaractive default value (e.g.
// data source attributes).
func ResolveMaxResults(v types.Int64) int {
	if v.IsNull() || v.IsUnknown() {
		return defaultMaxResults
	}
	return int(v.ValueInt64())
}

// PageFetcher returns the next batch of records, the API-reported total
// matching the caller's filter (or any non-positive number when the API does
// not report a total), and whether more pages exist after this one.
//
// The caller owns whatever pagination state the underlying API requires
// (offset, page number, cursor token); each call should advance that state.
// hasMore is the authoritative signal — the loop stops as soon as it sees
// hasMore == false, even if maxResults has not been reached.
type PageFetcher[T any] func(ctx context.Context) (page []T, totalCount int, hasMore bool, err error)

// AccumulateAll walks fetchPage until any of the following terminate the loop:
//
//  1. fetchPage reports hasMore == false (the last page).
//  2. The accumulated count reaches maxResults.
//  3. The first page reports a totalCount that exceeds maxResults — in this
//     case AccumulateAll returns a [*MaxResultsExceededError] rather than
//     silently truncating.
//  4. ctx is cancelled.
//
// maxResults == 0 disables the cap and accumulates every record fetchPage
// returns. resourceLabel is used in the cap-exceeded error message and should
// be the plural noun for the resource (e.g. "standards", "users").
//
// AccumulateAll never sleeps between calls; rate limiting belongs in the
// caller's fetchPage closure if needed.
func AccumulateAll[T any](
	ctx context.Context,
	maxResults int,
	resourceLabel string,
	fetchPage PageFetcher[T],
) ([]T, error) {
	var accumulated []T

	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		page, totalCount, hasMore, err := fetchPage(ctx)
		if err != nil {
			return nil, err
		}

		// Refuse to silently truncate: if the very first page tells us there
		// are more matching records than max_results allows, surface the
		// problem instead of returning a partial result the practitioner
		// hasn't asked for. We only check the first page because totalCount
		// can drift across pages under concurrent writes; the inner cap
		// check below still trims any overshoot from later pages.
		if accumulated == nil && maxResults > 0 && totalCount > maxResults {
			return nil, &MaxResultsExceededError{
				TotalCount:    totalCount,
				MaxResults:    maxResults,
				ResourceLabel: resourceLabel,
			}
		}

		accumulated = append(accumulated, page...)

		// Stop when we've reached the cap. Trim any overshoot from the final
		// page so the caller never sees more than max_results records.
		if maxResults > 0 && len(accumulated) >= maxResults {
			if len(accumulated) > maxResults {
				accumulated = accumulated[:maxResults]
			}
			return accumulated, nil
		}

		if !hasMore {
			return accumulated, nil
		}
	}
}

// OffsetPageFetcher fetches a single page given a 0-based searchFrom offset
// and an inclusive searchTo bound. It returns the page slice, the API's
// total_count for the matching set, and any error. This matches the shape of
// most Cortex Cloud List* endpoints today.
type OffsetPageFetcher[T any] func(ctx context.Context, searchFrom, searchTo int) (page []T, totalCount int, err error)

// OffsetAccumulateAll walks an offset-paginated API by repeatedly calling
// fetchPage with windows of pageSize records. It is a thin wrapper around
// [AccumulateAll]: termination conditions, the [MaxResultsExceededError]
// sentinel, and the maxResults / resourceLabel semantics are identical.
//
// The internal page size is fixed at pageSize records per call. pageSize must
// be greater than zero; OffsetAccumulateAll returns an error if it is not.
// The loop stops when fetchPage returns fewer than pageSize records (the
// last-page signal), when maxResults is reached, when the first-page
// total_count exceeds maxResults, or when ctx is cancelled.
func OffsetAccumulateAll[T any](
	ctx context.Context,
	pageSize int,
	maxResults int,
	resourceLabel string,
	fetchPage OffsetPageFetcher[T],
) ([]T, error) {
	if pageSize <= 0 {
		return nil, errors.New("pagination: pageSize must be greater than zero")
	}

	offset := 0
	adapter := func(ctx context.Context) ([]T, int, bool, error) {
		page, totalCount, err := fetchPage(ctx, offset, offset+pageSize-1)
		if err != nil {
			return nil, 0, false, err
		}
		// A short page means we just consumed the last one — no more pages.
		hasMore := len(page) >= pageSize
		offset += pageSize
		return page, totalCount, hasMore, nil
	}

	return AccumulateAll(ctx, maxResults, resourceLabel, adapter)
}
