/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 *
 * mosdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mosdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package doh_whitelist

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/miekg/dns"
	"go.uber.org/zap"

	"github.com/pmkol/mosdns-x/coremain"
	"github.com/pmkol/mosdns-x/pkg/dnsutils"
	"github.com/pmkol/mosdns-x/pkg/executable_seq"
	"github.com/pmkol/mosdns-x/pkg/matcher/netlist"
	"github.com/pmkol/mosdns-x/pkg/query_context"
)

const PluginType = "doh_whitelist"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() interface{} { return new(Args) })
}

var _ coremain.ExecutablePlugin = (*whitelist)(nil)

type Args struct {
	Whitelist   []string           `yaml:"whitelist"`    // IP addresses or CIDR ranges
	PathList    []string           `yaml:"path_list"`    // Allowed URL paths (e.g., /dns-query/token123)
	PathECS     map[string]PathECS `yaml:"path_ecs"`     // Path to ECS IP mapping
	RCode       int                `yaml:"rcode"`        // Response code when client is not in whitelist, default is REFUSED
	RequireBoth bool               `yaml:"require_both"` // If true, both IP and path must match; if false, either one matches (default: false)
}

// PathECS defines ECS configuration for a specific path
type PathECS struct {
	IPv4  string `yaml:"ipv4"`  // IPv4 address for ECS
	IPv6  string `yaml:"ipv6"`  // IPv6 address for ECS
	Mask4 int    `yaml:"mask4"` // IPv4 subnet mask (default: 24)
	Mask6 int    `yaml:"mask6"` // IPv6 subnet mask (default: 48)
}

type pathECSConfig struct {
	ipv4  netip.Addr
	ipv6  netip.Addr
	mask4 uint8
	mask6 uint8
}

type whitelist struct {
	*coremain.BP
	ipMatcher   *netlist.MatcherGroup
	pathList    map[string]struct{}       // Set of allowed paths
	pathECS     map[string]*pathECSConfig // Path to ECS configuration mapping
	rcode       int
	requireBoth bool
}

func Init(bp *coremain.BP, args interface{}) (p coremain.Plugin, err error) {
	return newWhitelist(bp, args.(*Args))
}

func newWhitelist(bp *coremain.BP, args *Args) (*whitelist, error) {
	rcode := args.RCode
	if rcode == 0 {
		rcode = dns.RcodeRefused
	}

	var ipMatcher *netlist.MatcherGroup
	if len(args.Whitelist) > 0 {
		// Load IP whitelist from configuration
		mg, err := netlist.BatchLoadProvider(args.Whitelist, bp.M().GetDataManager())
		if err != nil {
			return nil, fmt.Errorf("failed to load IP whitelist: %w", err)
		}
		ipMatcher = mg
		bp.L().Info("doh IP whitelist loaded", zap.Int("count", mg.Len()))
	}

	// Load path whitelist
	pathList := make(map[string]struct{})
	for _, path := range args.PathList {
		// Normalize path: remove trailing slash, ensure leading slash
		path = normalizePath(path)
		if path != "" {
			pathList[path] = struct{}{}
		}
	}
	if len(pathList) > 0 {
		bp.L().Info("doh path whitelist loaded", zap.Int("count", len(pathList)))
	}

	// Load path ECS configuration
	pathECS := make(map[string]*pathECSConfig)
	for path, ecsConfig := range args.PathECS {
		normalizedPath := normalizePath(path)
		if normalizedPath == "" {
			continue
		}

		config := &pathECSConfig{
			mask4: 24, // default IPv4 mask
			mask6: 48, // default IPv6 mask
		}

		// Validate and set masks
		if ecsConfig.Mask4 != 0 {
			if ecsConfig.Mask4 < 0 || ecsConfig.Mask4 > 32 {
				return nil, fmt.Errorf("invalid mask4 %d for path %s, should be between 0~32", ecsConfig.Mask4, path)
			}
			config.mask4 = uint8(ecsConfig.Mask4)
		}
		if ecsConfig.Mask6 != 0 {
			if ecsConfig.Mask6 < 0 || ecsConfig.Mask6 > 128 {
				return nil, fmt.Errorf("invalid mask6 %d for path %s, should be between 0~128", ecsConfig.Mask6, path)
			}
			config.mask6 = uint8(ecsConfig.Mask6)
		}

		// Parse IPv4
		if ecsConfig.IPv4 != "" {
			addr, err := netip.ParseAddr(ecsConfig.IPv4)
			if err != nil {
				return nil, fmt.Errorf("invalid ipv4 address %s for path %s: %w", ecsConfig.IPv4, path, err)
			}
			if !addr.Is4() {
				return nil, fmt.Errorf("ipv4 address %s for path %s is not a valid IPv4 address", ecsConfig.IPv4, path)
			}
			config.ipv4 = addr
		}

		// Parse IPv6
		if ecsConfig.IPv6 != "" {
			addr, err := netip.ParseAddr(ecsConfig.IPv6)
			if err != nil {
				return nil, fmt.Errorf("invalid ipv6 address %s for path %s: %w", ecsConfig.IPv6, path, err)
			}
			if !addr.Is6() {
				return nil, fmt.Errorf("ipv6 address %s for path %s is not a valid IPv6 address", ecsConfig.IPv6, path)
			}
			config.ipv6 = addr
		}

		// Check if at least one IP is configured
		if !config.ipv4.IsValid() && !config.ipv6.IsValid() {
			return nil, fmt.Errorf("path %s must have at least one of ipv4 or ipv6 configured", path)
		}

		pathECS[normalizedPath] = config
		bp.L().Info("doh path ECS configured", zap.String("path", normalizedPath),
			zap.Stringer("ipv4", config.ipv4), zap.Stringer("ipv6", config.ipv6),
			zap.Uint8("mask4", config.mask4), zap.Uint8("mask6", config.mask6))
	}
	if len(pathECS) > 0 {
		bp.L().Info("doh path ECS loaded", zap.Int("count", len(pathECS)))
	}

	// Check if at least one whitelist is configured
	if ipMatcher == nil && len(pathList) == 0 && len(pathECS) == 0 {
		return nil, fmt.Errorf("at least one of 'whitelist', 'path_list', or 'path_ecs' must be configured")
	}

	return &whitelist{
		BP:          bp,
		ipMatcher:   ipMatcher,
		pathList:    pathList,
		pathECS:     pathECS,
		rcode:       rcode,
		requireBoth: args.RequireBoth,
	}, nil
}

func normalizePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	path = strings.TrimSuffix(path, "/")
	if path == "" {
		path = "/"
	}
	return path
}

// Exec checks if the DoH client is in the whitelist (IP or path).
// If the request is not DoH, it passes through.
// If the client is not in whitelist, it returns a refused response.
func (w *whitelist) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
	// Check if this is a DoH request
	protocol := qCtx.ReqMeta().GetProtocol()
	isDoH := protocol == query_context.ProtocolHTTPS ||
		protocol == query_context.ProtocolH2 ||
		protocol == query_context.ProtocolH3

	// If not DoH, pass through
	if !isDoH {
		return executable_seq.ExecChainNode(ctx, qCtx, next)
	}

	// Check IP whitelist
	ipMatched := false
	if w.ipMatcher != nil {
		clientAddr := qCtx.ReqMeta().GetClientAddr()
		if clientAddr.IsValid() {
			matched, err := w.ipMatcher.Match(clientAddr)
			if err != nil {
				w.L().Warn("failed to match client address", zap.Stringer("addr", clientAddr), zap.Error(err))
			} else {
				ipMatched = matched
			}
		}
	} else {
		// If no IP whitelist configured, consider IP check as passed (when requireBoth is false)
		ipMatched = !w.requireBoth
	}

	// Get and normalize request path
	requestPath := normalizePath(qCtx.ReqMeta().GetPath())

	// Check path whitelist (path_list and path_ecs both qualify as allowed paths)
	pathConfigured := len(w.pathList) > 0 || len(w.pathECS) > 0
	pathMatched := false
	if pathConfigured {
		if _, ok := w.pathList[requestPath]; ok {
			pathMatched = true
		} else if _, ok := w.pathECS[requestPath]; ok {
			pathMatched = true
		}
	} else {
		// If no path whitelist configured, consider path check as passed (when requireBoth is false)
		pathMatched = !w.requireBoth
	}

	// Determine if request should be allowed
	allowed := false
	if w.requireBoth {
		// Both IP and path must match
		allowed = ipMatched && pathMatched
	} else {
		// Either IP or path matches
		allowed = ipMatched || pathMatched
	}

	if !allowed {
		// Request is not allowed, reject
		r := dnsutils.GenEmptyReply(qCtx.Q(), w.rcode)
		qCtx.SetResponse(r)
		return nil
	}

	// Request is allowed, add ECS if configured for this path
	if ecsConfig, ok := w.pathECS[requestPath]; ok {
		w.addECSForPath(qCtx, ecsConfig)
	}

	// Continue processing
	return executable_seq.ExecChainNode(ctx, qCtx, next)
}

// addECSForPath adds ECS information to the query based on path configuration
func (w *whitelist) addECSForPath(qCtx *query_context.Context, config *pathECSConfig) {
	q := qCtx.Q()
	opt := q.IsEdns0()
	hasECS := opt != nil && dnsutils.GetECS(opt) != nil

	// If ECS already exists, skip (don't overwrite)
	if hasECS {
		return
	}

	// Determine which IP to use based on query type
	var ecs *dns.EDNS0_SUBNET
	qType := dns.TypeA
	if len(q.Question) > 0 {
		qType = q.Question[0].Qtype
	}

	switch qType {
	case dns.TypeA:
		// Prefer IPv4 for A queries
		if config.ipv4.IsValid() {
			ecs = dnsutils.NewEDNS0Subnet(config.ipv4.AsSlice(), config.mask4, false)
		} else if config.ipv6.IsValid() {
			ecs = dnsutils.NewEDNS0Subnet(config.ipv6.AsSlice(), config.mask6, true)
		}
	case dns.TypeAAAA:
		// Prefer IPv6 for AAAA queries
		if config.ipv6.IsValid() {
			ecs = dnsutils.NewEDNS0Subnet(config.ipv6.AsSlice(), config.mask6, true)
		} else if config.ipv4.IsValid() {
			ecs = dnsutils.NewEDNS0Subnet(config.ipv4.AsSlice(), config.mask4, false)
		}
	default:
		// For other query types, prefer IPv4 if available
		if config.ipv4.IsValid() {
			ecs = dnsutils.NewEDNS0Subnet(config.ipv4.AsSlice(), config.mask4, false)
		} else if config.ipv6.IsValid() {
			ecs = dnsutils.NewEDNS0Subnet(config.ipv6.AsSlice(), config.mask6, true)
		}
	}

	if ecs != nil {
		if opt == nil {
			opt = dnsutils.UpgradeEDNS0(q)
		}
		dnsutils.AddECS(opt, ecs, true)
		// Log ECS IP address
		if addr, ok := netip.AddrFromSlice(ecs.Address); ok {
			w.L().Debug("added ECS for path", zap.String("path", qCtx.ReqMeta().GetPath()),
				zap.Stringer("ecs_ip", addr), zap.Uint8("mask", ecs.SourceNetmask))
		}
	}
}

func (w *whitelist) Close() error {
	if w.ipMatcher != nil {
		return w.ipMatcher.Close()
	}
	return nil
}
