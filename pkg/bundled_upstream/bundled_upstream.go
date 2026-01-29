/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 *
 * mosdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mosdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package bundled_upstream

import (
	"context"
	"errors"
	"sync"

	"github.com/miekg/dns"
	"go.uber.org/zap"

	"github.com/pmkol/mosdns-x/pkg/query_context"
)

type Upstream interface {
	// Exchange sends q to the upstream and waits for response.
	// If any error occurs, implementations must return a nil msg with a non-nil error.
	// Otherwise, implementations must return a msg with nil error.
	Exchange(ctx context.Context, q *dns.Msg) (*dns.Msg, error)

	// Trusted indicates whether this Upstream is trusted/reliable.
	// If true, responses from this Upstream will be accepted without checking its rcode.
	// Per spec: The first upstream is always trusted and cannot be changed.
	// Other upstreams only accept responses with RcodeSuccess.
	Trusted() bool

	// Address returns the upstream server address for logging purposes.
	Address() string
}

type parallelResult struct {
	r    *dns.Msg
	err  error
	from Upstream
}

var nopLogger = zap.NewNop()
var ErrAllFailed = errors.New("all upstreams failed")

// ExchangeParallel sends queries to multiple upstreams in parallel and returns the first acceptable response.
//
// Response acceptance rules:
//   - Trusted upstreams: Accept ANY rcode (including NXDOMAIN, SERVFAIL, etc.)
//   - Untrusted upstreams: Accept ONLY RcodeSuccess (0)
//   - Error responses from untrusted upstreams are discarded
//
// Optimization:
//   - Returns immediately when receiving the first acceptable response
//   - Cancels all pending upstream requests to save resources
//   - Uses buffered channel to prevent goroutine blocking
//
// Returns:
//   - First acceptable DNS response with nil error, OR
//   - nil response with ErrAllFailed if all upstreams fail or return unacceptable responses
func ExchangeParallel(ctx context.Context, qCtx *query_context.Context, upstreams []Upstream, logger *zap.Logger) (*dns.Msg, error) {
	if logger == nil {
		logger = nopLogger
	}

	t := len(upstreams)
	if t == 0 {
		return nil, ErrAllFailed
	}

	q := qCtx.Q()

	// Fast path: single upstream - no parallelization needed
	if t == 1 {
		return upstreams[0].Exchange(ctx, q)
	}

	// Create cancellable context for early termination
	taskCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	c := make(chan *parallelResult, t) // Buffered to prevent goroutine blocking

	// Launch all upstream queries in parallel
	for _, u := range upstreams {
		u := u
		qCopy := q.Copy() // Each goroutine needs its own copy
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := u.Exchange(taskCtx, qCopy)
			
			// Try to send result, but respect cancellation
			select {
			case c <- &parallelResult{r: r, err: err, from: u}:
			case <-taskCtx.Done():
				return
			}
		}()
	}

	// Close channel when all goroutines finish
	go func() {
		wg.Wait()
		close(c)
	}()

	// Collect results until we get an acceptable response or all fail
	for res := range c {
		// Handle network/exchange errors
		if res.err != nil {
			// Context errors are expected during early cancellation - log as debug
			if errors.Is(res.err, context.Canceled) || errors.Is(res.err, context.DeadlineExceeded) {
				logger.Debug("upstream canceled or timed out",
					qCtx.InfoField(),
					zap.String("addr", res.from.Address()))
				continue
			}

			// Network/DNS errors are unexpected - log as warning
			logger.Warn("upstream exchange failed",
				qCtx.InfoField(),
				zap.String("addr", res.from.Address()),
				zap.Error(res.err))
			continue
		}

		// Skip nil responses
		if res.r == nil {
			continue
		}

		// Accept response if:
		// 1. From trusted upstream (any rcode - including errors), OR
		// 2. From untrusted upstream with RcodeSuccess only
		//
		// This implements the spec:
		// "可信服务器的任何应答都会被接受。其余服务器只接受 RCODE 为 0 (SUCCESS) 的应答"
		if res.from.Trusted() || res.r.Rcode == dns.RcodeSuccess {
			cancel() // Stop all other pending requests immediately
			return res.r, nil
		}

		// Discard error responses from untrusted upstreams (per spec)
		// This is not an error - it's expected behavior
		logger.Debug("discarded untrusted error response",
			qCtx.InfoField(),
			zap.String("addr", res.from.Address()),
			zap.String("rcode", dns.RcodeToString[res.r.Rcode]))
	}

	// All upstreams failed or returned unacceptable responses
	return nil, ErrAllFailed
}
