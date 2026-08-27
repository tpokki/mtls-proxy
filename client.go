package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// defaultReloadInterval bounds how often certificate files are re-examined.
// Certificates are commonly rotated by an external process while the proxy is
// running, so they are reloaded in place rather than requiring a restart.
const defaultReloadInterval = 30 * time.Second

// identity is a single named mTLS client identity.
//
// Each identity owns its own http.Client and http.Transport. This is not an
// optimisation detail but a correctness requirement: TLS client certificates
// are negotiated once per connection, and http.Transport pools connections by
// destination address. A transport shared between two identities would happily
// serve a request for one identity over a connection established with the
// other's certificate, producing intermittent and load-dependent
// misattribution.
type identity struct {
	name     string
	target   string
	certPath string
	keyPath  string

	reloadEvery time.Duration

	mu        sync.RWMutex
	client    *http.Client
	transport *http.Transport
	notAfter  time.Time
	certMod   time.Time
	keyMod    time.Time
	lastCheck time.Time
}

// newIdentity creates an identity and performs the initial certificate load,
// so that a misconfigured path fails at startup rather than on first request.
func newIdentity(name, target, certPath, keyPath string, reloadEvery time.Duration) (*identity, error) {
	i := &identity{
		name:        name,
		target:      target,
		certPath:    certPath,
		keyPath:     keyPath,
		reloadEvery: reloadEvery,
	}

	i.mu.Lock()
	defer i.mu.Unlock()

	if err := i.loadLocked(); err != nil {
		return nil, err
	}
	i.lastCheck = time.Now()

	return i, nil
}

// loadLocked reads the certificate pair from disk and installs a fresh client
// and transport. The caller must hold the write lock.
func (i *identity) loadLocked() error {
	// Modification times are sampled before reading, so that a change made
	// while the file is being read is noticed by the next check rather than
	// being masked by a newer timestamp recorded after the fact.
	certMod, keyMod := fileModTimes(i.certPath, i.keyPath)

	cert, err := tls.LoadX509KeyPair(i.certPath, i.keyPath)
	if err != nil {
		return fmt.Errorf("client %q: load certificate: %w", i.displayName(), err)
	}

	leaf := cert.Leaf
	if leaf == nil {
		leaf, err = x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return fmt.Errorf("client %q: parse certificate: %w", i.displayName(), err)
		}
	}

	transport := newTransport(cert)

	// Replace the previous transport only once the new one is ready, and
	// close its idle connections so that no pooled connection continues to
	// present the superseded certificate.
	if i.transport != nil {
		i.transport.CloseIdleConnections()
	}

	i.transport = transport
	i.client = &http.Client{
		Transport: transport,
		// Redirects are returned to the caller rather than followed. A
		// proxy that follows them would both hide the redirect from the
		// caller and risk presenting the client certificate to whichever
		// host the upstream nominates.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	i.notAfter = leaf.NotAfter
	i.certMod, i.keyMod = certMod, keyMod

	return nil
}

// httpClient returns the client to use for this identity, reloading the
// certificate first if the files on disk have changed.
//
// A failed reload is not fatal: the previous certificate keeps being served.
// Certificates are frequently delivered by an external sync process, so a
// transient read of a partially written file must not take the proxy down.
func (i *identity) httpClient() *http.Client {
	i.mu.RLock()
	fresh := time.Since(i.lastCheck) < i.reloadEvery
	client := i.client
	i.mu.RUnlock()

	if fresh {
		return client
	}

	i.mu.Lock()
	defer i.mu.Unlock()

	// Another goroutine may have refreshed while the write lock was
	// contended.
	if time.Since(i.lastCheck) < i.reloadEvery {
		return i.client
	}
	i.lastCheck = time.Now()

	certMod, keyMod := fileModTimes(i.certPath, i.keyPath)
	if certMod.Equal(i.certMod) && keyMod.Equal(i.keyMod) {
		return i.client
	}

	previous := i.notAfter
	if err := i.loadLocked(); err != nil {
		logInfo("🟠 %s reload failed, keeping previous certificate: %v", i.logPrefix(), err)
		return i.client
	}

	logInfo("🟢 %s reloaded certificate, valid until %s (was %s)",
		i.logPrefix(), i.notAfter.Format(time.RFC3339), previous.Format(time.RFC3339))

	return i.client
}

// expiry returns the notAfter timestamp of the loaded certificate.
func (i *identity) expiry() time.Time {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.notAfter
}

// displayName renders the identity for messages, naming the implicit default
// identity explicitly since it has no configured name.
func (i *identity) displayName() string {
	if i.name == "" {
		return "default"
	}
	return i.name
}

// logPrefix renders the identity for log lines.
func (i *identity) logPrefix() string {
	return "[" + i.displayName() + "]"
}

// upstreamRootCAs overrides the system root pool used to verify the upstream.
// It is nil in normal operation and set only by tests, which talk to a server
// using an ad hoc certificate authority.
var upstreamRootCAs *x509.CertPool

// newTransport builds a transport pinned to a single client certificate.
//
// Transport.Proxy is deliberately left unset. The upstream is reached
// directly, as it was before several certificates were supported; honouring
// HTTPS_PROXY here would silently reroute traffic for anyone who happens to
// have it exported.
func newTransport(cert tls.Certificate) *http.Transport {
	return &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      upstreamRootCAs,
			MinVersion:   tls.VersionTLS12,
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

// fileModTimes returns the modification times of the certificate and key,
// using the zero time for files that cannot be stat'ed.
func fileModTimes(certPath, keyPath string) (time.Time, time.Time) {
	var certMod, keyMod time.Time
	if info, err := os.Stat(certPath); err == nil {
		certMod = info.ModTime()
	}
	if info, err := os.Stat(keyPath); err == nil {
		keyMod = info.ModTime()
	}
	return certMod, keyMod
}

// Registry holds the configured identities and resolves a name to one of them.
type Registry struct {
	byName   map[string]*identity
	order    []string
	fallback *identity
}

// NewRegistry builds a registry from configuration. The fallback identity, if
// any, is used when a request selects no client of its own.
func NewRegistry(cfg *Config, fallback *identity, reloadEvery time.Duration) (*Registry, error) {
	r := &Registry{
		byName:   make(map[string]*identity, len(cfg.Clients)),
		order:    make([]string, 0, len(cfg.Clients)),
		fallback: fallback,
	}

	for _, client := range cfg.Clients {
		id, err := newIdentity(client.Name, cfg.targetFor(client), client.Cert, client.Key, reloadEvery)
		if err != nil {
			return nil, err
		}

		r.byName[strings.ToLower(client.Name)] = id
		r.order = append(r.order, client.Name)

		logInfo("🟢 %s certificate valid until %s, forwarding to %s",
			id.logPrefix(), id.expiry().Format(time.RFC3339), id.target)
	}

	if fallback != nil {
		logInfo("🟢 %s certificate valid until %s, forwarding to %s",
			fallback.logPrefix(), fallback.expiry().Format(time.RFC3339), fallback.target)
	}

	return r, nil
}

// Lookup resolves a client name. Matching is case-insensitive, since the name
// arrives in a request header typed by a human.
func (r *Registry) Lookup(name string) (*identity, bool) {
	id, ok := r.byName[strings.ToLower(strings.TrimSpace(name))]
	return id, ok
}

// Fallback returns the identity used when a request selects no client, or nil
// when none is configured.
func (r *Registry) Fallback() *identity {
	return r.fallback
}

// Names lists the configured client names in declaration order, for use in
// error messages.
func (r *Registry) Names() []string {
	return r.order
}

// Empty reports whether the registry holds no named clients.
func (r *Registry) Empty() bool {
	return len(r.byName) == 0
}
