/*
 * Copyright (C) 2020-2026, IrineSistiana
 */

package limit_ip

import (
	"context"
	"math/rand"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/pmkol/mosdns-x/coremain"
	"github.com/pmkol/mosdns-x/pkg/executable_seq"
	"github.com/pmkol/mosdns-x/pkg/query_context"
)

const PluginType = "limit_ip"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() interface{} {
		return new(Args)
	})
}

type Args struct {
	Limit int `yaml:"limit"`
}

type limitIPPlugin struct {
	*coremain.BP
	limit int

	// rand.Rand is not thread-safe. Protecting with mutex.
	randMu  sync.Mutex
	randSrc *rand.Rand
}

func Init(bp *coremain.BP, args interface{}) (coremain.Plugin, error) {
	cfg := args.(*Args)
	limit := cfg.Limit
	if limit <= 0 {
		limit = 3
	}
	return &limitIPPlugin{
		BP:      bp,
		limit:   limit,
		randSrc: rand.New(rand.NewSource(time.Now().UnixNano())),
	}, nil
}

func (p *limitIPPlugin) Exec(
	ctx context.Context,
	qCtx *query_context.Context,
	next executable_seq.ExecutableChainNode,
) error {
	// Execute upstream first
	if err := executable_seq.ExecChainNode(ctx, qCtx, next); err != nil {
		return err
	}

	r := qCtx.R()
	// Early exit if answer is empty or has only one record
	if r == nil || len(r.Answer) <= 1 {
		return nil
	}

	// 1. Collect IP pointers (A/AAAA)
	// We don't need dns.Copy() here because we are only shuffling positions, 
	// not mutating the record content.
	var ipRRs []dns.RR
	for _, rr := range r.Answer {
		if t := rr.Header().Rrtype; t == dns.TypeA || t == dns.TypeAAAA {
			ipRRs = append(ipRRs, rr)
		}
	}

	// Exit if no IPs to shuffle or limit
	if len(ipRRs) == 0 {
		return nil
	}

	// 2. Thread-safe Shuffle for Round-Robin
	if len(ipRRs) > 1 {
		p.randMu.Lock()
		p.randSrc.Shuffle(len(ipRRs), func(i, j int) {
			ipRRs[i], ipRRs[j] = ipRRs[j], ipRRs[i]
		})
		p.randMu.Unlock()
	}

	// 3. Apply Limit
	if len(ipRRs) > p.limit {
		ipRRs = ipRRs[:p.limit]
	}

	// 4. Reconstruct Answer: Replace IPs in their original slots
	// This preserves the original record ordering (e.g. CNAME in middle)
	ipIdx := 0
	newAnswer := make([]dns.RR, 0, len(r.Answer))
	for _, rr := range r.Answer {
		switch rr.Header().Rrtype {
		case dns.TypeA, dns.TypeAAAA:
			// Fill the IP slots with shuffled/limited pointers
			if ipIdx < len(ipRRs) {
				newAnswer = append(newAnswer, ipRRs[ipIdx])
				ipIdx++
			}
			// If we reached the limit, the remaining original IP slots are skipped
		default:
			// Non-IP records are kept exactly where they were
			newAnswer = append(newAnswer, rr)
		}
	}

	r.Answer = newAnswer
	return nil
}
