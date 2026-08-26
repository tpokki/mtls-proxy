# mtls-proxy

Small utility that starts a local http server, and forwards all requests to a remote endpoint that requires mTLS authentication.

Tools that cannot easily be configured with a client certificate — or that only accept one certificate per host — can instead talk plain HTTP to this proxy and let it handle the mTLS handshake.

## Usage

### A single certificate

```sh
./mtls-proxy -target remote.host.example.com -certificate cert.crt -key private.key -port 8080
curl http://localhost:8080
```

### Several certificates, selected per request

Give the proxy a configuration file naming each certificate, and a request header to choose between them:

```yaml
target: remote.host.example.com

selector:
  header: X-Client-Name

clients:
  - name: alpha
    cert: /path/to/alpha.crt
    key: /path/to/alpha.key
  - name: beta
    cert: /path/to/beta.crt
    key: /path/to/beta.key
```

```sh
./mtls-proxy -config config.yaml
curl -H "X-Client-Name: alpha" http://localhost:8080
curl -H "X-Client-Name: beta"  http://localhost:8080
```

Both the header name and the client names are arbitrary — pick whatever suits the upstream. See [`config.example.yaml`](config.example.yaml) for every option.

## Configuration

| Key | Description |
| --- | --- |
| `listen` | Address to bind. Defaults to `127.0.0.1:8080`. |
| `target` | Upstream host used by clients that do not override it. |
| `selector.header` | Request header naming the client to use. When unset, `selector.default` serves every request. |
| `selector.default` | Client used when the header is absent or empty. Requests are rejected when unset. |
| `selector.passthrough` | Forward the selector header upstream. Defaults to `false`. |
| `clients[].name` | Name matched against the selector header, case-insensitively. |
| `clients[].cert` | Path to the client certificate. |
| `clients[].key` | Path to the private key. |
| `clients[].target` | Optional upstream host for this client only. |

## Command line

| Flag | Description |
| --- | --- |
| `-config` | Path to a YAML configuration file. |
| `-target` | Upstream host. Overrides `target` from the configuration file. |
| `-certificate` | Client certificate file. Defaults to `certificate.crt`. |
| `-key` | Private key file. Defaults to `private.key`. |
| `-listen` | Address to bind, e.g. `127.0.0.1:8080`. Overrides `-port` and `listen`. |
| `-port` | Port to listen on, bound to loopback. Defaults to `8080`. |
| `-reload-interval` | How often certificate files are checked for changes. Defaults to `30s`. |
| `-verbose` | Log level: `none`, `info` or `debug`. Defaults to `info`. |

A certificate given with `-certificate` and `-key` serves requests that select no client, so the two forms can be combined: named clients handle requests carrying the header, and the command line certificate handles the rest.

`-verbose` still works as a bare flag, as it did before log levels existed. Pass a level with `-verbose=debug`; note that `-verbose debug` will not work, since the value must be attached.

## Certificate rotation

Certificate files are re-read when they change on disk, so a certificate replaced by an external process is picked up without restarting the proxy. Files are checked at most once per `-reload-interval`.

If a reload fails — a partially written file during a sync, for instance — the previous certificate stays in use and a warning is logged.

## Notes

- **The proxy listens on loopback only by default.** It holds usable client certificates, and binding to every interface would offer them to anyone able to reach the machine. Use `-listen` if you genuinely need to expose it.
- **Redirects are returned to the caller rather than followed**, so that the client certificate is never presented to whichever host the upstream nominates.
- **The upstream is reached directly**, ignoring `HTTPS_PROXY` and similar environment variables.
- Each client gets its own connection pool. Sharing one between certificates would let a pooled connection carry a request for the wrong identity.

## Building

```sh
make            # build for darwin-arm64, linux-amd64 and windows-amd64 into bin/
go test ./...
```
