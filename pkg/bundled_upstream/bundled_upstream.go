/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
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
	Exchange(ctx context.Context, q *dns.Msg) (*dns.Msg, error)
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

	for res := range c {
		if res.err != nil {
			logger.Debug("upstream exchange failed",
				qCtx.InfoField(),
				zap.String("addr", res.from.Address()),
				zap.Error(res.err))
			continue
		}

		if res.r == nil {
			continue
		}

		if res.from.Trusted() || res.r.Rcode == dns.RcodeSuccess {
			cancel()
			return res.r, nil
		}

		logger.Debug("discarded untrusted error response",
			qCtx.InfoField(),
			zap.String("addr", res.from.Address()),
			zap.String("rcode", dns.RcodeToString[res.r.Rcode]))
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	return nil, ErrAllFailed
}
