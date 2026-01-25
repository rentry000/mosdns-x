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

package server

import (
	"context"
	"io"
	"net"
	"net/url"
	"time"

	"gitlab.com/go-extension/http"
	H "github.com/pmkol/mosdns-x/pkg/server/http_handler"
)

const (
	// Timeout for reading request headers (TLS handshake + HTTP headers)
	defaultReadHeaderTimeout = 3 * time.Second
	
	// Timeout for reading entire request (headers + body + handler processing)
	// Should be larger than DNS handler timeout (5s) to allow proper handling
	defaultReadTimeout = 10 * time.Second
	
	// Timeout for writing response to client
	defaultWriteTimeout = 10 * time.Second
	
	// Maximum size of request headers (4KB is standard for most web servers)
	defaultMaxHeaderBytes = 4096
)

func (s *Server) ServeHTTP(l net.Listener) error {
	defer l.Close()
	
	if s.opts.HttpHandler == nil {
		return errMissingHTTPHandler
	}
	
	// IdleTimeout is for keep-alive connections between requests
	idleTimeout := s.opts.IdleTimeout
	if idleTimeout == 0 {
		idleTimeout = defaultTCPIdleTimeout
	}
	
	hs := &http.Server{
		Handler: &eHandler{s.opts.HttpHandler},
		
		// ReadHeaderTimeout: Time to read request headers
		// Must account for TLS handshake (~200-500ms) + header parsing
		ReadHeaderTimeout: defaultReadHeaderTimeout,
		
		// ReadTimeout: Total time to read request and process handler
		// Must be > DNS handler timeout (5s) to prevent premature timeouts
		ReadTimeout: defaultReadTimeout,
		
		// WriteTimeout: Time to write response to client
		// Protects against slow clients and ensures resources are freed
		WriteTimeout: defaultWriteTimeout,
		
		// IdleTimeout: Time to keep connection alive between requests (keep-alive)
		// Can be much longer as connection is idle, not processing
		IdleTimeout: idleTimeout,
		
		// MaxHeaderBytes: Maximum size of request headers
		// 4KB is sufficient for DNS-over-HTTPS and standard HTTP headers
		MaxHeaderBytes: defaultMaxHeaderBytes,
	}
	
	if ok := s.trackCloser(hs, true); !ok {
		return ErrServerClosed
	}
	defer s.trackCloser(hs, false)
	
	err := hs.Serve(l)
	if err == http.ErrServerClosed {
		// Replace http.ErrServerClosed with our ErrServerClosed
		return ErrServerClosed
	}
	return err
}

type eHandler struct {
	h *H.Handler
}

func (h *eHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.h.ServeHTTP(&eWriter{w}, &eRequest{r})
}

type eRequest struct {
	r *http.Request
}

func (r *eRequest) URL() *url.URL {
	return r.r.URL
}

func (r *eRequest) TLS() *H.TlsInfo {
	if r.r.TLS == nil {
		return nil
	}
	return &H.TlsInfo{
		Version:            r.r.TLS.Version,
		ServerName:         r.r.TLS.ServerName,
		NegotiatedProtocol: r.r.TLS.NegotiatedProtocol,
	}
}

func (r *eRequest) Body() io.ReadCloser {
	return r.r.Body
}

func (r *eRequest) Header() H.Header {
	return r.r.Header
}

func (r *eRequest) Method() string {
	return r.r.Method
}

func (r *eRequest) Context() context.Context {
	return r.r.Context()
}

func (r *eRequest) RequestURI() string {
	return r.r.RequestURI
}

func (r *eRequest) GetRemoteAddr() string {
	return r.r.RemoteAddr
}

func (r *eRequest) SetRemoteAddr(addr string) {
	r.r.RemoteAddr = addr
}

type eWriter struct {
	w http.ResponseWriter
}

func (w *eWriter) Header() H.Header {
	return w.w.Header()
}

func (w *eWriter) Write(b []byte) (int, error) {
	return w.w.Write(b)
}

func (w *eWriter) WriteHeader(statusCode int) {
	w.w.WriteHeader(statusCode)
}
