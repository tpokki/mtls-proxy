package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// hopByHopHeaders are connection-scoped and must not be forwarded to the
// upstream or copied back to the caller.
var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Proxy-Connection",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// ForwardHandler forwards incoming plain HTTP requests to an upstream that
// requires mTLS authentication, choosing the client certificate to present
// based on a configurable request header.
type ForwardHandler struct {
	registry *Registry
	selector Selector
}

// NewForwardHandler creates a handler for the given registry and selector.
func NewForwardHandler(registry *Registry, selector Selector) *ForwardHandler {
	return &ForwardHandler{registry: registry, selector: selector}
}

func (f *ForwardHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	id, err := f.resolve(r)
	if err != nil {
		logInfo("🔴 %s %s: %v", r.Method, r.URL.Path, err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	fr := r.Clone(r.Context())
	fr.URL.Scheme = "https"
	fr.URL.Host = id.target
	// Host is carried separately from URL.Host and takes precedence when the
	// request is written, so it must be retargeted too. Left unset it would
	// send the proxy's own listen address upstream.
	fr.Host = id.target
	fr.RequestURI = ""
	// Close is copied by Clone and is written out as "Connection: close"
	// independently of the header map, so deleting the header below is not
	// enough to stop an inbound close request from propagating upstream and
	// suppressing connection reuse.
	fr.Close = false

	if !f.selector.Passthrough && f.selector.Header != "" {
		fr.Header.Del(f.selector.Header)
	}
	for _, header := range hopByHopHeaders {
		fr.Header.Del(header)
	}

	logDebug("🔵 %s %s %s -> %s", id.logPrefix(), fr.Method, fr.URL.Path, fr.URL.Host)

	resp, err := id.httpClient().Do(fr)
	if err != nil {
		logInfo("🔴 %s %s %s", id.logPrefix(), fr.Method, fr.URL.Path)
		logInfo("🔴 %s %s", id.logPrefix(), err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	logInfo("🟢 %s %s %s [%d]", id.logPrefix(), fr.Method, fr.URL.Path, resp.StatusCode)

	body := resp.Body
	if debugEnabled() {
		// The body is consumed to log it, so it is replaced with an
		// equivalent reader for the copy below. Reading it away without
		// restoring it would return an empty response to the caller.
		captured, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			logInfo("🔴 %s reading response body: %v", id.logPrefix(), readErr)
			http.Error(w, readErr.Error(), http.StatusInternalServerError)
			return
		}
		logDebug("🔵 %s response headers:\n--- HEADERS ---\n%+v", id.logPrefix(), resp.Header)
		logDebug("🔵 %s response body:\n--- BODY ---\n%s", id.logPrefix(), string(captured))
		body = io.NopCloser(bytes.NewReader(captured))
	}

	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	for _, header := range hopByHopHeaders {
		w.Header().Del(header)
	}

	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, body); err != nil {
		logInfo("🔴 %s copying response body: %v", id.logPrefix(), err)
	}
}

// resolve determines which client identity should serve a request.
//
// Selection failures are reported as errors rather than being allowed to
// proceed, so that a misspelled or missing client name surfaces as a clear
// message instead of an opaque TLS failure from the upstream.
func (f *ForwardHandler) resolve(r *http.Request) (*identity, error) {
	name := ""
	if f.selector.Header != "" {
		name = strings.TrimSpace(r.Header.Get(f.selector.Header))
	}

	// A request that names no client falls back to the configured default,
	// which also covers the case of a configuration with clients but no
	// selector header, where one identity serves everything.
	fromHeader := name != ""
	if name == "" {
		name = f.selector.Default
	}

	if name == "" {
		if fallback := f.registry.Fallback(); fallback != nil {
			return fallback, nil
		}
		if f.selector.Header == "" {
			return nil, fmt.Errorf("no client certificate configured")
		}
		return nil, fmt.Errorf(
			"no client selected: set the %s header to one of: %s",
			f.selector.Header, f.availableClients())
	}

	id, ok := f.registry.Lookup(name)
	if !ok {
		if fromHeader {
			return nil, fmt.Errorf(
				"unknown client %q in %s header; available clients: %s",
				name, f.selector.Header, f.availableClients())
		}
		return nil, fmt.Errorf(
			"default client %q is not configured; available clients: %s",
			name, f.availableClients())
	}

	return id, nil
}

// availableClients renders the selectable client names for error messages.
func (f *ForwardHandler) availableClients() string {
	names := f.registry.Names()
	if len(names) == 0 {
		return "none configured"
	}
	return strings.Join(names, ", ")
}
