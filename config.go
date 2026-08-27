package main

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the file-based configuration for the proxy. It describes a set of
// named client identities and how an incoming request selects between them.
//
// The proxy is deliberately agnostic about what the selector header is called
// and what the clients are named; both are supplied by the operator.
type Config struct {
	// Listen is the local address to bind, e.g. "127.0.0.1:8080".
	Listen string `yaml:"listen"`

	// Target is the default upstream host used by clients that do not
	// specify one of their own.
	Target string `yaml:"target"`

	Selector Selector `yaml:"selector"`
	Clients  []Client `yaml:"clients"`
}

// Selector describes how a request is mapped to a client identity.
type Selector struct {
	// Header names the request header carrying the client name. When empty,
	// per-request selection is disabled and every request uses the client
	// named by Default, or the certificate given on the command line.
	Header string `yaml:"header"`

	// Default names the client used when the header is absent or empty. When
	// empty, and no certificate was given on the command line, a request
	// without the header is rejected.
	Default string `yaml:"default"`

	// Passthrough keeps the selector header on the forwarded request. By
	// default the header is treated as proxy metadata and removed, since
	// upstreams generally have no use for it.
	Passthrough bool `yaml:"passthrough"`
}

// Client is a named mTLS identity: a certificate/key pair, and optionally an
// upstream host that overrides the global target.
type Client struct {
	Name   string `yaml:"name"`
	Cert   string `yaml:"cert"`
	Key    string `yaml:"key"`
	Target string `yaml:"target"`
}

// LoadConfig reads and validates a YAML configuration file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}

	return &cfg, nil
}

// Validate reports whether the configuration is internally consistent. It is
// called after command line overrides have been merged in, so that a target
// supplied on the command line can satisfy a client that omits one.
func (c *Config) Validate() error {
	seen := make(map[string]string, len(c.Clients))

	for i, client := range c.Clients {
		if client.Name == "" {
			return fmt.Errorf("clients[%d]: name is required", i)
		}

		key := strings.ToLower(client.Name)
		if previous, dup := seen[key]; dup {
			return fmt.Errorf("clients[%d]: duplicate name %q (conflicts with %q; names are case-insensitive)", i, client.Name, previous)
		}
		seen[key] = client.Name

		if client.Cert == "" {
			return fmt.Errorf("client %q: cert is required", client.Name)
		}
		if client.Key == "" {
			return fmt.Errorf("client %q: key is required", client.Name)
		}
		if client.Target == "" && c.Target == "" {
			return fmt.Errorf("client %q: no target set, and no global target to fall back to", client.Name)
		}
	}

	if c.Selector.Default != "" {
		if _, ok := seen[strings.ToLower(c.Selector.Default)]; !ok {
			return fmt.Errorf("selector.default %q does not name a configured client (available: %s)", c.Selector.Default, c.clientNames())
		}
	}

	// A selector header without clients cannot select anything. This is
	// almost certainly a mistake rather than an intentional configuration.
	if c.Selector.Header != "" && len(c.Clients) == 0 {
		return fmt.Errorf("selector.header is set but no clients are configured")
	}

	return nil
}

// clientNames returns the configured client names in declaration order, for
// use in error messages.
func (c *Config) clientNames() string {
	if len(c.Clients) == 0 {
		return "none configured"
	}

	names := make([]string, 0, len(c.Clients))
	for _, client := range c.Clients {
		names = append(names, client.Name)
	}
	return strings.Join(names, ", ")
}

// targetFor returns the upstream host for a client, falling back to the global
// target when the client does not override it.
func (c *Config) targetFor(client Client) string {
	if client.Target != "" {
		return client.Target
	}
	return c.Target
}
