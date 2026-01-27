/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 */

package cache

import (
	"context"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/golang/snappy"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	"golang.org/x/sync/singleflight"

	"github.com/pmkol/mosdns-x/coremain"
	"github.com/pmkol/mosdns-x/pkg/cache"
	"github.com/pmkol/mosdns-x/pkg/cache/mem_cache"
	"github.com/pmkol/mosdns-x/pkg/cache/redis_cache"
	"github.com/pmkol/mosdns-x/pkg/dnsutils"
	"github.com/pmkol/mosdns-x/pkg/executable_seq"
	"github.com/pmkol/mosdns-x/pkg/pool"
	"github.com/pmkol/mosdns-x/pkg/query_context"
)

const PluginType = "cache"

const (
	defaultLazyUpdateTimeout = 5 * time.Second
	defaultEmptyAnswerTTL    = 300 * time.Second
)

var _ coremain.ExecutablePlugin = (*cachePlugin)(nil)

type Args struct {
	Size              int    `yaml:"size"`
	Redis             string `yaml:"redis"`
	RedisTimeout      int    `yaml:"redis_timeout"`
	LazyCacheTTL      int    `yaml:"lazy_cache_ttl"`
	LazyCacheReplyTTL int    `yaml:"lazy_cache_reply_ttl"`
	CacheEverything   bool   `yaml:"cache_everything"`
	CompressResp      bool   `yaml:"compress_resp"`
	WhenHit           string `yaml:"when_hit"`
}

type cachePlugin struct {
	*coremain.BP
	args *Args

	whenHit      executable_seq.Executable
	backend      cache.Backend
	lazyUpdateSF singleflight.Group

	queryTotal   prometheus.Counter
	hitTotal     prometheus.Counter
	lazyHitTotal prometheus.Counter
	size         prometheus.GaugeFunc
}

func Init(bp *coremain.BP, args interface{}) (coremain.Plugin, error) {
	return newCachePlugin(bp, args.(*Args))
}

func newCachePlugin(bp *coremain.BP, args *Args) (*cachePlugin, error) {
	var backend cache.Backend

	if args.Redis != "" {
		opt, err := redis.ParseURL(args.Redis)
		if err != nil {
			return nil, err
		}
		opt.MaxRetries = -1
		r := redis.NewClient(opt)

		backend, err = redis_cache.NewRedisCache(redis_cache.RedisCacheOpts{
			Client:        r,
			ClientCloser:  r,
			ClientTimeout: time.Duration(args.RedisTimeout) * time.Millisecond,
			Logger:        bp.L(),
		})
		if err != nil {
			return nil, err
		}
	} else {
		backend = mem_cache.NewMemCache(args.Size, 0)
	}

	if args.LazyCacheReplyTTL <= 0 {
		args.LazyCacheReplyTTL = 5
	}

	var whenHit executable_seq.Executable
	if args.WhenHit != "" {
		whenHit = bp.M().GetExecutables()[args.WhenHit]
		if whenHit == nil {
			return nil, fmt.Errorf("cannot find executable %s", args.WhenHit)
		}
	}

	p := &cachePlugin{
		BP:      bp,
		args:    args,
		whenHit: whenHit,
		backend: backend,

		queryTotal:   prometheus.NewCounter(prometheus.CounterOpts{Name: "query_total"}),
		hitTotal:     prometheus.NewCounter(prometheus.CounterOpts{Name: "hit_total"}),
		lazyHitTotal: prometheus.NewCounter(prometheus.CounterOpts{Name: "lazy_hit_total"}),
		size: prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "cache_size",
		}, func() float64 {
			return float64(backend.Len())
		}),
	}

	bp.GetMetricsReg().MustRegister(
		p.queryTotal,
		p.hitTotal,
		p.lazyHitTotal,
		p.size,
	)

	return p, nil
}

func (c *cachePlugin) Exec(
	ctx context.Context,
	qCtx *query_context.Context,
	next executable_seq.ExecutableChainNode,
) error {
	c.queryTotal.Inc()
	q := qCtx.Q()

	msgKey, err := c.getMsgKey(q)
	if err != nil || msgKey == "" {
		return executable_seq.ExecChainNode(ctx, qCtx, next)
	}

	cached, lazyHit, _ := c.lookupCache(msgKey)
	if lazyHit {
		c.lazyHitTotal.Inc()
		c.doLazyUpdate(msgKey, qCtx, next)
	}

	if cached != nil {
		c.hitTotal.Inc()
		cached.Id = q.Id
		qCtx.SetResponse(cached)
		if c.whenHit != nil {
			return c.whenHit.Exec(ctx, qCtx, nil)
		}
		return nil
	}

	err = executable_seq.ExecChainNode(ctx, qCtx, next)
	if r := qCtx.R(); r != nil {
		_ = c.tryStoreMsg(msgKey, r)
	}
	return err
}

func (c *cachePlugin) getMsgKey(q *dns.Msg) (string, error) {
	isSimple := len(q.Question) == 1 &&
		len(q.Answer) == 0 &&
		len(q.Ns) == 0 &&
		len(q.Extra) == 0

	if isSimple || c.args.CacheEverything {
		return dnsutils.GetMsgKey(q, 0)
	}

	if len(q.Question) == 1 {
		simple := *q
		simple.Answer = nil
		simple.Ns = nil
		simple.Extra = nil
		return dnsutils.GetMsgKey(&simple, 0)
	}

	return "", nil
}

func (c *cachePlugin) lookupCache(key string) (*dns.Msg, bool, error) {
	v, stored, _ := c.backend.Get(key)
	if v == nil {
		return nil, false, nil
	}

	if c.args.CompressResp {
		buf := pool.GetBuf(dns.MaxMsgSize)
		defer buf.Release()
		decoded, err := snappy.Decode(buf.Bytes(), v)
		if err != nil {
			return nil, false, err
		}
		v = append([]byte(nil), decoded...)
	}

	r := new(dns.Msg)
	if err := r.Unpack(v); err != nil {
		return nil, false, err
	}

	var ttl time.Duration
	if len(r.Answer) == 0 {
		ttl = defaultEmptyAnswerTTL
	} else {
		ttl = time.Duration(dnsutils.GetMinimalTTL(r)) * time.Second
	}

	if stored.Add(ttl).After(time.Now()) {
		dnsutils.SubtractTTL(r, uint32(time.Since(stored).Seconds()))
		return r, false, nil
	}

	if c.args.LazyCacheTTL > 0 {
		dnsutils.SetTTL(r, uint32(c.args.LazyCacheReplyTTL))
		return r, true, nil
	}

	return nil, false, nil
}

func (c *cachePlugin) doLazyUpdate(
	msgKey string,
	qCtx *query_context.Context,
	next executable_seq.ExecutableChainNode,
) {
	lazyQCtx := qCtx.Copy()

	go func() {
		c.lazyUpdateSF.DoChan(msgKey, func() (interface{}, error) {
			defer c.lazyUpdateSF.Forget(msgKey)

			ctx, cancel := context.WithTimeout(context.Background(), defaultLazyUpdateTimeout)
			defer cancel()
			ctx = context.WithValue(ctx, "mosdns_is_bg_update", true)

			if err := executable_seq.ExecChainNode(ctx, lazyQCtx, next); err != nil {
				c.L().Warn("lazy update failed", zap.Error(err))
				return nil, nil
			}

			if r := lazyQCtx.R(); r != nil {
				if err := c.tryStoreMsg(msgKey, r); err != nil {
					c.L().Error("lazy cache store failed", zap.Error(err))
				}
			}
			return nil, nil
		})
	}()
}

func (c *cachePlugin) tryStoreMsg(key string, r *dns.Msg) error {
	if r.Truncated {
		return nil
	}
	if r.Rcode != dns.RcodeSuccess && r.Rcode != dns.RcodeNameError {
		return nil
	}

	raw, err := r.Pack()
	if err != nil {
		return err
	}

	now := time.Now()
	var exp time.Time

	if c.args.LazyCacheTTL > 0 {
		exp = now.Add(time.Duration(c.args.LazyCacheTTL) * time.Second)
	} else {
		ttl := dnsutils.GetMinimalTTL(r)
		if ttl == 0 {
			return nil
		}
		exp = now.Add(time.Duration(ttl) * time.Second)
	}

	if c.args.CompressResp {
		buf := pool.GetBuf(snappy.MaxEncodedLen(len(raw)))
		defer buf.Release()
		encoded := snappy.Encode(buf.Bytes(), raw)
		raw = append([]byte(nil), encoded...)
	}

	c.backend.Store(key, raw, now, exp)
	return nil
}

func (c *cachePlugin) Shutdown() error {
	return c.backend.Close()
}
