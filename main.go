package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net/http"
)

type ForwardHandler struct {
	http.Handler
	client *http.Client
}

var port int
var target string
var certificate string
var privateKey string

// init binds flags for command line arguments
func init() {
	flag.IntVar(&port, "port", 8080, "port to listen on")
	flag.StringVar(&target, "target", "", "target host")
	flag.StringVar(&certificate, "certificate", "", "certificate file")
	flag.StringVar(&privateKey, "key", "", "key file")
}

// main creates local http server, and forwards all requests to the target server
// that uses mTLS authentication.
func main() {
	// Parse command line arguments
	flag.Parse()

	err := http.ListenAndServe(fmt.Sprintf(":%d", port), ForwardHandler{client: createClient()})
	fmt.Printf("exit: %+v\n", err)
}

func (f ForwardHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Forward request to target server
	fr := r.Clone(context.Background())
	fr.URL.Scheme = "https"
	fr.URL.Host = target
	fr.RequestURI = ""

	resp, err := f.client.Do(fr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Copy response from target server to local client
	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// createClient creates a http.Client that uses mTLS authentication
func createClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{loadCertificate(certificate, privateKey)},
			},
		},
	}
}

// loadCertificate loads a certificate from a file
func loadCertificate(certificate, privateKey string) tls.Certificate {
	cert, err := tls.LoadX509KeyPair(certificate, privateKey)
	if err != nil {
		panic(err)
	}
	return cert
}
