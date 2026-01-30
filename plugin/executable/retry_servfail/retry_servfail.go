package retry_servfail

import (
	"context"

	"github.com/miekg/dns"
	"github.com/pmkol/mosdns-x/coremain"
	"github.com/pmkol/mosdns-x/pkg/executable_seq"
	"github.com/pmkol/mosdns-x/pkg/query_context"
)

const (
	PluginType = "retry_servfail"
)

func init() {
	coremain.RegNewPersetPluginFunc("_retry_servfail", func(bp *coremain.BP) (coremain.Plugin, error) {
		return &retryServfail{BP: bp}, nil
	})
}

var _ coremain.ExecutablePlugin = (*retryServfail)(nil)

type retryServfail struct {
	*coremain.BP
}

func (t *retryServfail) Exec(
	ctx context.Context,
	qCtx *query_context.Context,
	next executable_seq.ExecutableChainNode,
) error {
	// 1st attempt: Execute the remaining chain (upstream and post-processors)
	if err := executable_seq.ExecChainNode(ctx, qCtx, next); err != nil {
		return err
	}

	r := qCtx.R()
	shouldRetry := false

	// Define failure conditions (Transport error or Transient SERVFAIL)
	if r == nil {
		shouldRetry = true
	} else if r.Rcode == dns.RcodeServerFailure && len(r.Ns) == 0 {
		shouldRetry = true
	}

	if shouldRetry {
		t.L().Debug("transient failure detected, retrying upstream", qCtx.InfoField())
		// Clear failed response state from context
		qCtx.SetResponse(nil)
		// 2nd attempt: Re-execute the remaining chain
		return executable_seq.ExecChainNode(ctx, qCtx, next)
	}

	return nil
}
