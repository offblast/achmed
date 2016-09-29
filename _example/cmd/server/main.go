package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net/http"

	"google.golang.org/grpc"

	"github.com/offblast/achmed"
)

var (
	achmedAddress = flag.String("achmed", "127.0.0.1:7654", "achmed address")
	address       = flag.String("address", ":443", "The server port")
)

func handler(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("This is an example server.\n"))
}

func main() {
	flag.Parse()

	achmedClient, err := achmed.New(*achmedAddress, grpc.WithInsecure())
	if err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/", handler)

	srv := &http.Server{
		Addr: *address,
		TLSConfig: &tls.Config{
			GetCertificate: achmedClient.GetCertificate,
		},
	}

	log.Printf("About to listen on %s", *address)

	err = srv.ListenAndServeTLS("", "")
	log.Fatal(err)
}
