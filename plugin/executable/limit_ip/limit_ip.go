package limit_ip

import (
	"context"
	"math/rand"
	"sync"

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

	shuffleMutex sync.Mutex
}

func Init(bp *coremain.BP, args interface{}) (coremain.Plugin, error) {
	cfg := args.(*Args)
	limit := cfg.Limit
	if limit <= 0 {
		limit = 3
	}
	return &limitIPPlugin{
		BP:    bp,
		limit: limit,
	}, nil
}

func (p *limitIPPlugin) shuffle(rrs []dns.RR) {
	p.shuffleMutex.Lock()
	defer p.shuffleMutex.Unlock()
	rand.Shuffle(len(rrs), func(i, j int) {
		rrs[i], rrs[j] = rrs[j], rrs[i]
	})
}

func (p *limitIPPlugin) Exec(
	ctx context.Context,
	qCtx *query_context.Context,
	next executable_seq.ExecutableChainNode,
) error {

	if err := executable_seq.ExecChainNode(ctx, qCtx, next); err != nil {
		return err
	}

	r := qCtx.R()
	if r == nil {
		return nil
	}

	var ipRRs []dns.RR
	var otherRRs []dns.RR

	for _, rr := range r.Answer {
		switch rr.Header().Rrtype {
		case dns.TypeA, dns.TypeAAAA:
			ipRRs = append(ipRRs, rr)
		default:
			otherRRs = append(otherRRs, rr)
		}
	}

	if len(ipRRs) > 1 {
		p.shuffle(ipRRs)
	}

	if len(ipRRs) > p.limit {
		ipRRs = ipRRs[:p.limit]
	}

	r.Answer = append(otherRRs, ipRRs...)
	return nil
}
