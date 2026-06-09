// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package pagination

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
)

const testPageSize = 100

// makeRange returns []int{start, start+1, ..., start+count-1}, used to build
// canned page payloads for the offset-pagination tests.
func makeRange(start, count int) []int {
	out := make([]int, count)
	for i := range out {
		out[i] = start + i
	}
	return out
}

// stubOffsetFetcher returns an OffsetPageFetcher that serves slices of
// universe in pageSize-sized windows aligned to the requested searchFrom.
// callCount is incremented on each invocation so tests can assert how many
// times the loop actually called the API.
func stubOffsetFetcher(universe []int, callCount *int) OffsetPageFetcher[int] {
	return func(_ context.Context, from, to int) ([]int, int, error) {
		*callCount++
		if from >= len(universe) {
			return nil, len(universe), nil
		}
		end := to + 1
		if end > len(universe) {
			end = len(universe)
		}
		return universe[from:end], len(universe), nil
	}
}

// --- OffsetAccumulateAll tests (the legacy compliance-style API) ----------

// TestOffsetAccumulateAll_SinglePageShortCircuit verifies the loop terminates
// after one call when the API returns fewer records than the page size.
func TestOffsetAccumulateAll_SinglePageShortCircuit(t *testing.T) {
	calls := 0
	got, err := OffsetAccumulateAll(context.Background(), testPageSize, 1000, "items", stubOffsetFetcher(makeRange(0, 25), &calls))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 25 {
		t.Errorf("expected 25 items, got %d", len(got))
	}
	if calls != 1 {
		t.Errorf("expected exactly 1 page fetch, got %d", calls)
	}
}

// TestOffsetAccumulateAll_MultiPageAccumulation verifies the loop walks past
// the first full page and continues until a short page is hit, preserving
// element order.
func TestOffsetAccumulateAll_MultiPageAccumulation(t *testing.T) {
	calls := 0
	universe := makeRange(0, 250) // 100 + 100 + 50
	got, err := OffsetAccumulateAll(context.Background(), testPageSize, 1000, "items", stubOffsetFetcher(universe, &calls))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 250 {
		t.Errorf("expected 250 items, got %d", len(got))
	}
	if calls != 3 {
		t.Errorf("expected 3 page fetches (100+100+50), got %d", calls)
	}
	if got[0] != 0 || got[249] != 249 {
		t.Errorf("page boundaries lost; got[0]=%d got[249]=%d", got[0], got[249])
	}
}

// TestOffsetAccumulateAll_ExactPageBoundary verifies termination when the
// universe size is an exact multiple of the page size: the loop must make one
// extra call that returns short (or empty) to know it has reached the end.
func TestOffsetAccumulateAll_ExactPageBoundary(t *testing.T) {
	calls := 0
	universe := makeRange(0, 200) // exactly 2 full pages
	got, err := OffsetAccumulateAll(context.Background(), testPageSize, 1000, "items", stubOffsetFetcher(universe, &calls))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 200 {
		t.Errorf("expected 200 items, got %d", len(got))
	}
	if calls != 3 {
		t.Errorf("expected 3 page fetches (100+100+empty), got %d", calls)
	}
}

// TestOffsetAccumulateAll_MaxResultsZeroDisablesCap verifies that passing 0
// for maxResults means "no cap" — every record is returned regardless of how
// large the universe is.
func TestOffsetAccumulateAll_MaxResultsZeroDisablesCap(t *testing.T) {
	calls := 0
	universe := makeRange(0, 350)
	got, err := OffsetAccumulateAll(context.Background(), testPageSize, 0, "items", stubOffsetFetcher(universe, &calls))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 350 {
		t.Errorf("expected 350 items, got %d", len(got))
	}
}

// TestOffsetAccumulateAll_MaxResultsCapExceededReturnsTypedError is the
// silent-truncation regression guard. When the API's total_count exceeds
// maxResults the function must return a [*MaxResultsExceededError] so callers
// can detect the condition with [errors.As] without parsing strings.
func TestOffsetAccumulateAll_MaxResultsCapExceededReturnsTypedError(t *testing.T) {
	calls := 0
	universe := makeRange(0, 5000)
	_, err := OffsetAccumulateAll(context.Background(), testPageSize, 1000, "standards", stubOffsetFetcher(universe, &calls))
	if err == nil {
		t.Fatal("expected an error when total_count > max_results, got nil")
	}

	var capErr *MaxResultsExceededError
	if !errors.As(err, &capErr) {
		t.Fatalf("expected *MaxResultsExceededError, got %T: %v", err, err)
	}
	if capErr.TotalCount != 5000 {
		t.Errorf("TotalCount = %d, want 5000", capErr.TotalCount)
	}
	if capErr.MaxResults != 1000 {
		t.Errorf("MaxResults = %d, want 1000", capErr.MaxResults)
	}
	if capErr.ResourceLabel != "standards" {
		t.Errorf("ResourceLabel = %q, want %q", capErr.ResourceLabel, "standards")
	}
	if calls != 1 {
		t.Errorf("expected exactly 1 fetch before erroring, got %d", calls)
	}
}

// TestOffsetAccumulateAll_MaxResultsCapMatchesTotal verifies the boundary
// case where total_count equals maxResults — the loop should accumulate
// exactly that many records without erroring, and should make exactly the
// expected number of API calls (10 = 1000 / 100).
func TestOffsetAccumulateAll_MaxResultsCapMatchesTotal(t *testing.T) {
	calls := 0
	universe := makeRange(0, 1000)
	got, err := OffsetAccumulateAll(context.Background(), testPageSize, 1000, "items", stubOffsetFetcher(universe, &calls))
	if err != nil {
		t.Fatalf("unexpected error at total==max boundary: %v", err)
	}
	if len(got) != 1000 {
		t.Errorf("expected 1000 items, got %d", len(got))
	}
	if calls != 10 {
		t.Errorf("expected exactly 10 page fetches (1000/100), got %d", calls)
	}
}

// TestOffsetAccumulateAll_FetcherErrorPropagated verifies an error from the
// fetcher closure is surfaced via errors.Is and not swallowed.
func TestOffsetAccumulateAll_FetcherErrorPropagated(t *testing.T) {
	wantErr := errors.New("API exploded")
	_, err := OffsetAccumulateAll(context.Background(), testPageSize, 1000, "items",
		func(_ context.Context, _, _ int) ([]int, int, error) {
			return nil, 0, wantErr
		},
	)
	if !errors.Is(err, wantErr) {
		t.Errorf("expected wrapped fetcher error, got: %v", err)
	}
}

// TestOffsetAccumulateAll_ContextCancellationHonoured verifies the loop
// checks ctx.Err() between pages and returns the cancellation error promptly
// without firing additional API calls.
func TestOffsetAccumulateAll_ContextCancellationHonoured(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	universe := makeRange(0, 500)

	fetcher := func(_ context.Context, from, to int) ([]int, int, error) {
		calls++
		if calls == 1 {
			cancel() // user hit Ctrl-C between pages 1 and 2
		}
		end := to + 1
		if end > len(universe) {
			end = len(universe)
		}
		return universe[from:end], len(universe), nil
	}

	_, err := OffsetAccumulateAll(ctx, testPageSize, 0, "items", fetcher)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
	if calls != 1 {
		t.Errorf("expected exactly 1 fetch before cancellation honoured, got %d", calls)
	}
}

// TestOffsetAccumulateAll_RejectsNonPositivePageSize is a defensive check —
// a zero or negative pageSize would cause an infinite loop, so we error out.
func TestOffsetAccumulateAll_RejectsNonPositivePageSize(t *testing.T) {
	cases := []int{0, -1, -100}
	for _, ps := range cases {
		_, err := OffsetAccumulateAll(context.Background(), ps, 1000, "items",
			func(_ context.Context, _, _ int) ([]int, int, error) {
				t.Fatal("fetcher must not be called when pageSize is invalid")
				return nil, 0, nil
			},
		)
		if err == nil {
			t.Errorf("pageSize=%d: expected an error, got nil", ps)
		}
	}
}

// --- AccumulateAll tests (the opaque-fetcher core loop) -------------------

// stubCursorFetcher returns a PageFetcher that drains universe in chunks of
// size, simulating a cursor-style API where the caller owns its own state.
func stubCursorFetcher(t *testing.T, universe []int, size int, callCount *int) PageFetcher[int] {
	t.Helper()
	var consumed int
	return func(_ context.Context) ([]int, int, bool, error) {
		*callCount++
		if consumed >= len(universe) {
			return nil, len(universe), false, nil
		}
		end := consumed + size
		if end > len(universe) {
			end = len(universe)
		}
		page := universe[consumed:end]
		consumed = end
		hasMore := consumed < len(universe)
		return page, len(universe), hasMore, nil
	}
}

// TestAccumulateAll_HasMoreFalseTerminates verifies the loop respects the
// hasMore signal independently of how many records the page contained.
func TestAccumulateAll_HasMoreFalseTerminates(t *testing.T) {
	calls := 0
	universe := makeRange(0, 130)
	got, err := AccumulateAll(context.Background(), 1000, "items", stubCursorFetcher(t, universe, 50, &calls))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 130 {
		t.Errorf("expected 130 items, got %d", len(got))
	}
	if calls != 3 {
		t.Errorf("expected 3 page fetches (50+50+30), got %d", calls)
	}
}

// TestAccumulateAll_TypedErrorOnFirstPageOversize verifies the cap-exceeded
// error path works at the opaque-fetcher layer, not just the offset wrapper.
func TestAccumulateAll_TypedErrorOnFirstPageOversize(t *testing.T) {
	_, err := AccumulateAll(context.Background(), 100, "users", func(_ context.Context) ([]int, int, bool, error) {
		return makeRange(0, 50), 5000, true, nil
	})
	var capErr *MaxResultsExceededError
	if !errors.As(err, &capErr) {
		t.Fatalf("expected *MaxResultsExceededError, got %T: %v", err, err)
	}
	if capErr.TotalCount != 5000 || capErr.MaxResults != 100 || capErr.ResourceLabel != "users" {
		t.Errorf("unexpected fields: %+v", capErr)
	}
}

// TestAccumulateAll_TotalCountUnknownAccepted verifies the loop works with
// APIs that do not report a total_count (it just won't trigger the
// first-page cap-exceeded branch). The maxResults trim still applies.
func TestAccumulateAll_TotalCountUnknownAccepted(t *testing.T) {
	universe := makeRange(0, 250)
	calls := 0
	got, err := AccumulateAll(context.Background(), 1000, "items", func(_ context.Context) ([]int, int, bool, error) {
		calls++
		// totalCount = 0 simulates "API doesn't report total"
		switch calls {
		case 1:
			return universe[0:100], 0, true, nil
		case 2:
			return universe[100:200], 0, true, nil
		case 3:
			return universe[200:250], 0, false, nil
		}
		t.Fatalf("unexpected 4th call")
		return nil, 0, false, nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 250 {
		t.Errorf("expected 250 items, got %d", len(got))
	}
}

// TestAccumulateAll_MaxResultsTrimAcrossPages verifies a caller using a large
// page size still gets exactly maxResults items even if the final page would
// have pushed the accumulator past the cap.
func TestAccumulateAll_MaxResultsTrimAcrossPages(t *testing.T) {
	universe := makeRange(0, 250)
	calls := 0
	// Page size 100; total_count = 0 (unknown). Cap at 150 → expect exactly
	// 150 records and the loop to stop after the 2nd page (100 + 50 trimmed).
	got, err := AccumulateAll(context.Background(), 150, "items", func(_ context.Context) ([]int, int, bool, error) {
		calls++
		switch calls {
		case 1:
			return universe[0:100], 0, true, nil
		case 2:
			return universe[100:200], 0, true, nil
		}
		t.Fatalf("expected exactly 2 calls, got call #%d", calls)
		return nil, 0, false, nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 150 {
		t.Errorf("expected 150 items (trimmed), got %d", len(got))
	}
	if got[149] != 149 {
		t.Errorf("expected last element to be 149, got %d", got[149])
	}
	if calls != 2 {
		t.Errorf("expected exactly 2 fetches, got %d", calls)
	}
}

// --- ResolveMaxResults table -----------------------------------------------

func TestResolveMaxResults(t *testing.T) {
	tests := []struct {
		name string
		in   types.Int64
		want int
	}{
		{"null defaults to 1000", types.Int64Null(), defaultMaxResults},
		{"unknown defaults to 1000", types.Int64Unknown(), defaultMaxResults},
		{"explicit zero stays zero", types.Int64Value(0), 0},
		{"explicit value passes through", types.Int64Value(7500), 7500},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ResolveMaxResults(tt.in); got != tt.want {
				t.Errorf("ResolveMaxResults(%v) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}

// --- MaxResultsExceededError formatting ------------------------------------

// TestMaxResultsExceededError_MessageContainsAllFields verifies the default
// error string surfaces the three numbers/labels callers care about. This is
// the compatibility guarantee for the existing compliance acc tests that
// substring-match on "5000", "1000", and the resource label.
func TestMaxResultsExceededError_MessageContainsAllFields(t *testing.T) {
	err := &MaxResultsExceededError{TotalCount: 5000, MaxResults: 1000, ResourceLabel: "standards"}
	got := err.Error()
	for _, want := range []string{"5000", "1000", "standards"} {
		if !strings.Contains(got, want) {
			t.Errorf("error message missing %q in:\n%s", want, got)
		}
	}
}
