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

var _ coremain.ExecutablePlugin = (*limitIPPlugin)(nil)

type Args struct {
	Limit int `yaml:"limit"`
}

type limitIPPlugin struct {
	*coremain.BP
	limit int
}

func Init(bp *coremain.BP, args interface{}) (coremain.Plugin, error) {
    return newLimitIPPlugin(bp, args.(*Args)), nil
}

func newLimitIPPlugin(bp *coremain.BP, args *Args) *limitIPPlugin {
	limit := args.Limit
	if limit <= 0 {
		limit = 3
	}
	return &limitIPPlugin{
		BP:    bp,
		limit: limit,
	}
}

func (p *limitIPPlugin) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
    r := qCtx.R()
    
    if r == nil || len(r.Answer) <= p.limit {
        return executable_seq.ExecChainNode(ctx, qCtx, next)
    }

    w := 0
    ipCount := 0

    for _, rr := range r.Answer {
        h := rr.Header().Rrtype
        
        if h == dns.TypeA || h == dns.TypeAAAA {
            if ipCount < p.limit {
                r.Answer[w] = rr
                w++
                ipCount++
            }
        } else {
            r.Answer[w] = rr
            w++
        }
    }

    r.Answer = r.Answer[:w]

    return executable_seq.ExecChainNode(ctx, qCtx, next)
}