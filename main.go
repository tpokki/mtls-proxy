package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
)

type ForwardHandler struct {
	http.Handler
	client *http.Client
}

var port int
var target string
var certificate string
var privateKey string
var verbose bool

// init binds flags for command line arguments
func init() {
	flag.IntVar(&port, "port", 8080, "port to listen on")
	flag.StringVar(&target, "target", "", "target host")
	flag.StringVar(&certificate, "certificate", "certificate.crt", "certificate file")
	flag.StringVar(&privateKey, "key", "private.key", "key file")
	flag.BoolVar(&verbose, "verbose", true, "verbose output")
}

// main creates local http server, and forwards all requests to the target server
// that uses mTLS authentication.
func main() {
	// Parse command line arguments
	flag.Parse()

	// Check if target host is provided
	if target == "" {
		fmt.Printf("Target host is required\n\n")
		flag.Usage()
		os.Exit(1)
	}

	// set output verbosity
	if verbose {
		log.SetFlags(log.LstdFlags)
	} else {
		log.SetFlags(0)
		log.SetOutput(io.Discard)
	}

	log.Printf("🟢 Starting local forwarder to %s...\n", target)
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
		log.Printf("🔴 %s %s\n", fr.Method, fr.URL.Path)
		log.Printf("🔴 %s\n", err.Error())
		return
	}

	log.Printf("🟢 %s %s [%d]\n", fr.Method, fr.URL.Path, resp.StatusCode)

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
		fmt.Printf("%+v\n", err.Error())
		os.Exit(1)
	}
	return cert
}
