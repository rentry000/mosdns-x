/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 *
 * mosdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

package http_handler

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"reflect"
	"strings"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go/http3"
	"go.uber.org/zap"

	"github.com/pmkol/mosdns-x/pkg/dnsutils"
	"github.com/pmkol/mosdns-x/pkg/pool"
	C "github.com/pmkol/mosdns-x/pkg/query_context"
	"github.com/pmkol/mosdns-x/pkg/server/dns_handler"
)

var nopLogger = zap.NewNop()

type HandlerOpts struct {
	DNSHandler  dns_handler.Handler
	Path        string
	SrcIPHeader string
	HealthPath  string
	RedirectURL string
	Logger      *zap.Logger
}

func (opts *HandlerOpts) Init() error {
	if opts.DNSHandler == nil {
		return errors.New("nil dns handler")
	}
	if opts.Logger == nil {
		opts.Logger = nopLogger
	}
	if opts.HealthPath == "" {
		opts.HealthPath = "/health"
	}
	return nil
}

type Handler struct {
	opts HandlerOpts
}

func NewHandler(opts HandlerOpts) (*Handler, error) {
	if err := opts.Init(); err != nil {
		return nil, err
	}
	return &Handler{opts: opts}, nil
}

func (h *Handler) warnErr(req Request, err error) {
	h.opts.Logger.Warn(err.Error(), zap.String("from", req.GetRemoteAddr()), zap.String("method", req.Method()), zap.String("url", req.RequestURI()))
}

type ResponseWriter interface {
	Header() Header
	Write([]byte) (int, error)
	WriteHeader(statusCode int)
}

type Header interface {
	Get(key string) string
	Set(key string, value string)
}

type Request interface {
	URL() *url.URL
	TLS() *TlsInfo
	Body() io.ReadCloser
	Header() Header
	Method() string
	Context() context.Context
	RequestURI() string
	GetRemoteAddr() string
	SetRemoteAddr(addr string)
}

type TlsInfo struct {
	Version            uint16
	ServerName         string
	NegotiatedProtocol string
}

func (h *Handler) ServeHTTP(w ResponseWriter, req Request) {
	meta := new(C.RequestMeta)
	if addr, err := getRemoteAddr(req, h.opts.SrcIPHeader); err == nil {
		meta.SetClientAddr(addr)
	}

	if tlsInfo := req.TLS(); tlsInfo != nil {
		meta.SetServerName(tlsInfo.ServerName)
		switch tlsInfo.NegotiatedProtocol {
		case http3.NextProtoH3:
			meta.SetProtocol(C.ProtocolH3)
		case "h2":
			meta.SetProtocol(C.ProtocolH2)
		default:
			meta.SetProtocol(C.ProtocolHTTPS)
		}
	} else {
		meta.SetProtocol(C.ProtocolHTTP)
	}

	// 1. Health check - Always allow
	if h.opts.HealthPath != "" && req.URL().Path == h.opts.HealthPath {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
		return
	}

	// 2. Path & Root validation - Redirect browsers/scanners early
	if (len(h.opts.Path) != 0 && req.URL().Path != h.opts.Path) || req.URL().Path == "/" {
		if h.opts.RedirectURL != "" {
			w.Header().Set("Location", h.opts.RedirectURL)
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		return
	}

	var b []byte
	var err error

	switch req.Method() {
	case http.MethodGet:
		// 3. GET validation - Silent redirect for non-DoH Accept headers
		accept := req.Header().Get("Accept")
		var matched bool
		for _, v := range strings.Split(accept, ",") {
			mediatype := strings.TrimSpace(strings.SplitN(v, ";", 2)[0])
			if mediatype == "application/dns-message" {
				matched = true
				break
			}
		}

		if !matched {
			if h.opts.RedirectURL != "" {
				w.Header().Set("Location", h.opts.RedirectURL)
				w.WriteHeader(http.StatusFound)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		s := req.URL().Query().Get("dns")
		if len(s) == 0 {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("no dns param"))
			return
		}

		b, err = base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			h.warnErr(req, fmt.Errorf("decode base64 failed: %s", err))
			return
		}

	case http.MethodPost:
		// 4. POST validation - RFC 8484 strictly requires 4xx, no redirect
		if contentType := req.Header().Get("Content-Type"); contentType != "application/dns-message" {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("invalid Content-Type"))
			return
		}

		b, err = io.ReadAll(req.Body())
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// 5. DNS Unpack and Processing
	m := new(dns.Msg)
	if err := m.Unpack(b); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		h.warnErr(req, fmt.Errorf("unpack dns msg failed: %s", err))
		return
	}

	r, err := h.opts.DNSHandler.ServeDNS(req.Context(), m, meta)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		h.warnErr(req, fmt.Errorf("dns handler error: %s", err))
		return
	}

	b, buf, err := pool.PackBuffer(r)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		h.warnErr(req, fmt.Errorf("pack response failed: %s", err))
		return
	}
	defer buf.Release()

	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d", dnsutils.GetMinimalTTL(r)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
}

func getRemoteAddr(req Request, customHeader string) (netip.Addr, error) {
	if tcip := req.Header().Get("True-Client-IP"); tcip != "" {
		if addr, err := netip.ParseAddr(tcip); err == nil {
			req.SetRemoteAddr(tcip)
			return addr, nil
		}
	}
	if xrip := req.Header().Get("X-Real-IP"); xrip != "" {
		if addr, err := netip.ParseAddr(xrip); err == nil {
			req.SetRemoteAddr(xrip)
			return addr, nil
		}
	}
	if xff := req.Header().Get("X-Forwarded-For"); xff != "" {
		ip, _, _ := strings.Cut(xff, ",")
		if addr, err := netip.ParseAddr(ip); err == nil {
			req.SetRemoteAddr(ip)
			return addr, nil
		}
	}
	if customHeader != "" && !contain([]string{"True-Client-IP", "X-Real-IP", "X-Forwarded-For"}, customHeader) {
		if ip := req.Header().Get(customHeader); ip != "" {
			if addr, err := netip.ParseAddr(ip); err == nil {
				req.SetRemoteAddr(ip)
				return addr, nil
			}
		}
	}
	addrport, err := netip.ParseAddrPort(req.GetRemoteAddr())
	if err != nil {
		return netip.Addr{}, err
	}
	return addrport.Addr(), nil
}

func contain[T any](arr []T, it T) bool {
	for _, item := range arr {
		if reflect.DeepEqual(it, item) {
			return true
		}
	}
	return false
}
