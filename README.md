# mtls-proxy

Small utility that starts local http server, and forwards all requests to remote endpoint that requires mTLS authentication.

## Usage

```sh
./mtls-proxy -target remote.host.example.com -certificate cert.crt -key private.key -port 8080
curl http://localhost:8080
```
