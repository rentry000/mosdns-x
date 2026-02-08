package doh_whitelist

import (
	"context"
	"net/netip"
	"testing"

	"github.com/miekg/dns"
	"go.uber.org/zap"

	"github.com/pmkol/mosdns-x/coremain"
	"github.com/pmkol/mosdns-x/pkg/dnsutils"
	"github.com/pmkol/mosdns-x/pkg/executable_seq"
	"github.com/pmkol/mosdns-x/pkg/query_context"
)

// recordingNode is a simple ExecutableChainNode used to verify chaining.
type recordingNode struct {
	executable_seq.NodeLinker
	called bool
}

func (r *recordingNode) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
	r.called = true
	return executable_seq.ExecChainNode(ctx, qCtx, next)
}

func newTestWhitelist(pathList map[string]struct{}, pathECS map[string]*pathECSConfig, requireBoth bool) *whitelist {
	return &whitelist{
		BP:          coremain.NewBP("test", PluginType, zap.NewNop(), nil),
		pathList:    pathList,
		pathECS:     pathECS,
		rcode:       dns.RcodeRefused,
		requireBoth: requireBoth,
	}
}

func newDoHQCtx(path string) *query_context.Context {
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)

	meta := query_context.NewRequestMeta(netip.MustParseAddr("192.0.2.1"))
	meta.SetProtocol(query_context.ProtocolHTTPS)
	meta.SetPath(path)

	return query_context.NewContext(msg, meta)
}

func TestPathECSActsAsWhitelistAndAddsECS(t *testing.T) {
	ecsIP := netip.MustParseAddr("203.0.113.5")
	w := newTestWhitelist(nil, map[string]*pathECSConfig{
		"/dns-query/ecs": {
			ipv4:  ecsIP,
			mask4: 24,
		},
	}, false)

	qCtx := newDoHQCtx("/dns-query/ecs")
	recorder := &recordingNode{}

	if err := w.Exec(context.Background(), qCtx, recorder); err != nil {
		t.Fatalf("Exec returned error: %v", err)
	}

	if !recorder.called {
		t.Fatal("expected next node to be called for allowed DoH request")
	}

	opt := qCtx.Q().IsEdns0()
	ecs := dnsutils.GetECS(opt)
	if ecs == nil {
		t.Fatalf("expected ECS to be added for path, got nil")
	}

	if ecs.Family != 1 || ecs.SourceNetmask != 24 {
		t.Fatalf("unexpected ECS metadata: family=%d mask=%d", ecs.Family, ecs.SourceNetmask)
	}

	if addr, ok := netip.AddrFromSlice(ecs.Address); !ok || addr != ecsIP {
		t.Fatalf("unexpected ECS address: %v", ecs.Address)
	}
}

func TestRequestRejectedWhenPathNotAllowed(t *testing.T) {
	w := newTestWhitelist(nil, map[string]*pathECSConfig{
		"/dns-query/allowed": {
			ipv4:  netip.MustParseAddr("203.0.113.5"),
			mask4: 24,
		},
	}, false)

	qCtx := newDoHQCtx("/dns-query/other")
	recorder := &recordingNode{}

	if err := w.Exec(context.Background(), qCtx, recorder); err != nil {
		t.Fatalf("Exec returned error: %v", err)
	}

	if recorder.called {
		t.Fatal("expected chain not to continue when request is rejected")
	}

	if resp := qCtx.R(); resp == nil || resp.Rcode != dns.RcodeRefused {
		t.Fatalf("expected refused response, got %#v", resp)
	}
}

func TestNonDoHRequestsBypassWhitelist(t *testing.T) {
	w := newTestWhitelist(map[string]struct{}{"/dns-query/allowed": {}}, nil, false)

	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	meta := query_context.NewRequestMeta(netip.MustParseAddr("198.51.100.10"))
	meta.SetProtocol(query_context.ProtocolUDP)
	meta.SetPath("/dns-query/allowed")
	qCtx := query_context.NewContext(msg, meta)

	recorder := &recordingNode{}
	if err := w.Exec(context.Background(), qCtx, recorder); err != nil {
		t.Fatalf("Exec returned error: %v", err)
	}

	if !recorder.called {
		t.Fatal("expected non-DoH request to bypass whitelist and call next node")
	}

	if ecs := dnsutils.GetECS(qCtx.Q().IsEdns0()); ecs != nil {
		t.Fatalf("expected no ECS added for non-DoH requests, got %+v", ecs)
	}
}
