/*
 * Copyright (C) 2020-2026, IrineSistiana
 * Updated: Transport-centric Retry Logic (Fixed Error Propagation & Type Name)
 */

package retry_servfail

import (
	"context"
	"github.com/pmkol/mosdns-x/coremain"
	"github.com/pmkol/mosdns-x/pkg/executable_seq"
	"github.com/pmkol/mosdns-x/pkg/query_context"
)

const PluginType = "retry_servfail"

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
	// === Phase 1: First Attempt ===
	err := executable_seq.ExecChainNode(ctx, qCtx, next)

	// Decision Matrix:
	// - err != nil: Network timeout, connection reset, handshake failed, etc.
	// - qCtx.R() == nil: No response received despite no transport error.
	// - If qCtx.R() is present: Transport succeeded (even if Rcode is SERVFAIL).
	shouldRetry := err != nil || qCtx.R() == nil

	// === Phase 2: Conditional Retry ===
	if shouldRetry {
		// Verify if the client is still waiting (prevent ghost retries)
		if ctx.Err() != nil {
			return ctx.Err()
		}

		t.L().Debug("network transport failure detected, retrying upstream", qCtx.InfoField())

		// Reset failed state before re-execution
		qCtx.SetResponse(nil)

		// === Phase 3: Second Attempt ===
		// Overwrite 'err' with the result of the second attempt.
		err = executable_seq.ExecChainNode(ctx, qCtx, next)
	}

	// === Phase 4: Final Error Return ===
	return err
}
