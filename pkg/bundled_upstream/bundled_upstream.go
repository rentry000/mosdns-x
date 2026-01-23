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
	Exchange(ctx context.Context, q *dns.Msg) (*dns.Msg, error)

	// Trusted indicates whether this Upstream is trusted/reliable.
	Trusted() bool

	Address() string
}

type parallelResult struct {
	r    *dns.Msg
	err  error
	from Upstream
}

var nopLogger = zap.NewNop()

var ErrAllFailed = errors.New("all upstreams failed")

func ExchangeParallel(ctx context.Context, qCtx *query_context.Context, upstreams []Upstream, logger *zap.Logger) (*dns.Msg, error) {
	if logger == nil {
		logger = nopLogger
	}

	t := len(upstreams)
	if t == 0 {
		return nil, ErrAllFailed
	}

	q := qCtx.Q()
	if t == 1 {
		return upstreams[0].Exchange(ctx, q)
	}

	taskCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	c := make(chan *parallelResult, t)

	for _, u := range upstreams {
		u := u
		qCopy := q.Copy()

		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := u.Exchange(taskCtx, qCopy)
			select {
			case c <- &parallelResult{r: r, err: err, from: u}:
			case <-taskCtx.Done():
				return
			}
		}()
	}

	go func() {
		wg.Wait()
		close(c)
	}()

	var lastRes *dns.Msg
	var lastErr error

	// Idiomatic way to consume the channel until it's closed by the waiter goroutine
	for res := range c {
		if res.err != nil {
			// Suppress logging for context cancellation as it is an expected behavior
			if !errors.Is(res.err, context.Canceled) {
				logger.Warn("upstream failed",
					qCtx.InfoField(),
					zap.String("addr", res.from.Address()),
					zap.Error(res.err))
				lastErr = res.err
			}
			continue
		}

		if res.r == nil {
			continue
		}

		// Priority 1: Trusted upstream or Successful Rcode (0)
		if res.from.Trusted() || res.r.Rcode == dns.RcodeSuccess {
			cancel()
			return res.r, nil
		}

		// Priority 2: Prefer NXDOMAIN (NameError) over other Rcode errors
		if lastRes == nil || (res.r.Rcode == dns.RcodeNameError && lastRes.Rcode != dns.RcodeNameError) {
			lastRes = res.r
		}
	}

	// Fallback to the best non-success response found (e.g., NXDOMAIN)
	if lastRes != nil {
		return lastRes, nil
	}

	// If everything failed, return the last meaningful error
	if lastErr != nil && !errors.Is(lastErr, context.Canceled) {
		return nil, lastErr
	}

	return nil, ErrAllFailed
}
