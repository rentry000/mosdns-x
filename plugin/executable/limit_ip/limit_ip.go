package limit_ip

import (
	"context"
	"github.com/miekg/dns"
	"github.com/pmkol/mosdns-x/coremain"
	"github.com/pmkol/mosdns-x/pkg/executable_seq"
	"github.com/pmkol/mosdns-x/pkg/query_context"
)

const PluginType = "limit_ip"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() interface{} { return new(Args) })
}

type Args struct {
	Limit int `yaml:"limit"`
}

type limitIPPlugin struct {
	*coremain.BP
	limit int
}

func Init(bp *coremain.BP, args interface{}) (coremain.Plugin, error) {
	cfg := args.(*Args)
	limit := cfg.Limit
	if limit <= 0 {
		limit = 3
	}
	return &limitIPPlugin{BP: bp, limit: limit}, nil
}

func (p *limitIPPlugin) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
	if err := executable_seq.ExecChainNode(ctx, qCtx, next); err != nil {
		return err
	}
	
	r := qCtx.R()
	if r == nil {
		return nil
	}
	
	filtered := r.Answer[:0]
	ipCount := 0
	
	for _, rr := range r.Answer {
		if rr.Header().Rrtype == dns.TypeA || rr.Header().Rrtype == dns.TypeAAAA {
			if ipCount >= p.limit {
				continue
			}
			ipCount++
		}
		filtered = append(filtered, rr)
	}
	
	r.Answer = filtered
	return nil
}
