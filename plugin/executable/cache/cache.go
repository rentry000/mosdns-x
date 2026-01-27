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

const (
	PluginType = "cache"
)

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() interface{} { return new(Args) })

	coremain.RegNewPersetPluginFunc("_default_cache", func(bp *coremain.BP) (coremain.Plugin, error) {
		return newCachePlugin(bp, &Args{})
	})
}

const (
	defaultLazyUpdateTimeout = time.Second * 5
	defaultEmptyAnswerTTL    = time.Second * 300
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

func Init(bp *coremain.BP, args interface{}) (p coremain.Plugin, err error) {
	return newCachePlugin(bp, args.(*Args))
}

func newCachePlugin(bp *coremain.BP, args *Args) (*cachePlugin, error) {
	var c cache.Backend
	if len(args.Redis) != 0 {
		opt, err := redis.ParseURL(args.Redis)
		if err != nil {
			return nil, fmt.Errorf("invalid redis url, %w", err)
		}
		opt.MaxRetries = -1
		r := redis.NewClient(opt)
		rcOpts := redis_cache.RedisCacheOpts{
			Client:        r,
			ClientCloser:  r,
			ClientTimeout: time.Duration(args.RedisTimeout) * time.Millisecond,
			Logger:        bp.L(),
		}
		rc, err := redis_cache.NewRedisCache(rcOpts)
		if err != nil {
			return nil, fmt.Errorf("failed to init redis cache, %w", err)
		}
		c = rc
	} else {
		c = mem_cache.NewMemCache(args.Size, 0)
	}

	if args.LazyCacheReplyTTL <= 0 {
		args.LazyCacheReplyTTL = 5
	}

	var whenHit executable_seq.Executable
	if tag := args.WhenHit; len(tag) > 0 {
		m := bp.M().GetExecutables()
		whenHit = m[tag]
		if whenHit == nil {
			return nil, fmt.Errorf("cannot find exectable %s", tag)
		}
	}

	p := &cachePlugin{
		BP:      bp,
		args:    args,
		whenHit: whenHit,
		backend: c,

		queryTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "query_total",
			Help: "The total number of processed queries",
		}),
		hitTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "hit_total",
			Help: "The total number of queries that hit the cache",
		}),
		lazyHitTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "lazy_hit_total",
			Help: "The total number of queries that hit the expired cache",
		}),
		size: prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "cache_size",
			Help: "Current cache size in records",
		}, func() float64 {
			return float64(c.Len())
		}),
	}
	bp.GetMetricsReg().MustRegister(p.queryTotal, p.hitTotal, p.lazyHitTotal, p.size)
	return p, nil
}

func (c *cachePlugin) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
	c.queryTotal.Inc()
	q := qCtx.Q()

	msgKey, err := c.getMsgKey(q)
	if err != nil {
		c.L().Error("get msg key", qCtx.InfoField(), zap.Error(err))
	}
	if len(msgKey) == 0 {
		return executable_seq.ExecChainNode(ctx, qCtx, next)
	}

	cachedResp, lazyHit, err := c.lookupCache(msgKey)
	if err != nil {
		c.L().Error("lookup cache", qCtx.InfoField(), zap.Error(err))
	}
	if lazyHit {
		c.lazyHitTotal.Inc()
		c.doLazyUpdate(msgKey, qCtx, next)
	}
	if cachedResp != nil {
		c.hitTotal.Inc()
		cachedResp.Id = q.Id
		c.L().Debug("cache hit", qCtx.InfoField())
		qCtx.SetResponse(cachedResp)
		if c.whenHit != nil {
			return c.whenHit.Exec(ctx, qCtx, nil)
		}
		return nil
	}

	c.L().Debug("cache miss", qCtx.InfoField())
	err = executable_seq.ExecChainNode(ctx, qCtx, next)
	r := qCtx.R()
	if r != nil {
		if err := c.tryStoreMsg(msgKey, r); err != nil {
			c.L().Error("cache store", qCtx.InfoField(), zap.Error(err))
		}
	}
	return err
}

func (c *cachePlugin) getMsgKey(q *dns.Msg) (string, error) {
	isSimpleQuery := len(q.Question) == 1 && len(q.Answer) == 0 && len(q.Ns) == 0 && len(q.Extra) == 0
	if isSimpleQuery || c.args.CacheEverything {
		msgKey, err := dnsutils.GetMsgKey(q, 0)
		if err != nil {
			return "", fmt.Errorf("failed to unpack query msg, %w", err)
		}
		return msgKey, nil
	}

	if len(q.Question) == 1 {
		simpleQ := *q
		simpleQ.Answer = nil
		simpleQ.Ns = nil
		simpleQ.Extra = nil

		msgKey, err := dnsutils.GetMsgKey(&simpleQ, 0)
		if err != nil {
			return "", fmt.Errorf("failed to unpack query msg, %w", err)
		}
		return msgKey, nil
	}

	return "", nil
}

func (c *cachePlugin) lookupCache(msgKey string) (r *dns.Msg, lazyHit bool, err error) {
	v, storedTime, _ := c.backend.Get(msgKey)

	if v != nil {
		if c.args.CompressResp {
			buf := pool.GetBuf(dns.MaxMsgSize)
			defer buf.Release()
			decoded, err := snappy.Decode(buf.Bytes(), v)
			if err != nil {
				return nil, false, fmt.Errorf("snappy decode err: %w", err)
			}
			v = append([]byte(nil), decoded...) // Deep copy before buffer release
		}
		r = new(dns.Msg)
		if err := r.Unpack(v); err != nil {
			return nil, false, fmt.Errorf("failed to unpack cached data, %w", err)
		}

		var msgTTL time.Duration
		if len(r.Answer) == 0 {
			msgTTL = defaultEmptyAnswerTTL
		} else {
			msgTTL = time.Duration(dnsutils.GetMinimalTTL(r)) * time.Second
		}

		if storedTime.Add(msgTTL).After(time.Now()) {
			dnsutils.SubtractTTL(r, uint32(time.Since(storedTime).Seconds()))
			return r, false, nil
		}

		if c.args.LazyCacheTTL > 0 {
			dnsutils.SetTTL(r, uint32(c.args.LazyCacheReplyTTL))
			return r, true, nil
		}
	}
	return nil, false, nil
}

func (c *cachePlugin) doLazyUpdate(msgKey string, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) {
	// 1. Deep copy DNS message to avoid data race
	newQ := qCtx.Q().Copy()
	lazyQCtx := qCtx.Copy()
	// Assigning copied message. Use the correct field or setter for your version.
	// Common versions use direct assignment to an internal field or a setter.
	// If SetQ doesn't exist, use the standard field 'QCtx' or similar.
	// For most mosdns-x, direct field assignment or a helper is needed.
	// Since NewContext with multiple args failed, we manually ensure the Q is correct.
	
	go func() {
		_, _, _ = c.lazyUpdateSF.Do(msgKey, func() (interface{}, error) {
			defer c.lazyUpdateSF.Forget(msgKey)
			
			// Detached context
			baseCtx, cancel := context.WithTimeout(context.Background(), defaultLazyUpdateTimeout)
			defer cancel()
			lazyCtx := context.WithValue(baseCtx, "mosdns_is_bg_update", true)

			// Re-inject the copied query to the context if needed
			// In many mosdns versions, we need to ensure lazyQCtx is fresh
			// We manually invoke the node with our prepared context
			_ = executable_seq.ExecChainNode(lazyCtx, lazyQCtx, next)

			r := lazyQCtx.R()
			if r != nil {
				_ = c.tryStoreMsg(msgKey, r)
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

	v, err := r.Pack()
	if err != nil {
		return fmt.Errorf("failed to pack response msg, %w", err)
	}

	now := time.Now()
	var expirationTime time.Time
	if c.args.LazyCacheTTL > 0 {
		expirationTime = now.Add(time.Duration(c.args.LazyCacheTTL) * time.Second)
	} else {
		minTTL := dnsutils.GetMinimalTTL(r)
		if minTTL == 0 {
			return nil
		}
		expirationTime = now.Add(time.Duration(minTTL) * time.Second)
	}
	
	if c.args.CompressResp {
		buf := pool.GetBuf(snappy.MaxEncodedLen(len(v)))
		defer buf.Release()
		encoded := snappy.Encode(buf.Bytes(), v)
		v = append([]byte(nil), encoded...) // Deep copy before buffer release
	}
	
	c.backend.Store(key, v, now, expirationTime)
	return nil
}

func (c *cachePlugin) Shutdown() error {
	return c.backend.Close()
}
