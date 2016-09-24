package main

import (
	"flag"
	"net"
	"os"
	"os/signal"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/grpclog"

	"github.com/offblast/achmed/server"
)

var (
	tls      = flag.Bool("tls", false, "Connection uses TLS if true, else plain TCP")
	certFile = flag.String("cert_file", "testdata/server1.pem", "The TLS cert file")
	keyFile  = flag.String("key_file", "testdata/server1.key", "The TLS key file")
	acmeDB   = flag.String("db", "acme.cache", "a file for acme certificate caching")
	address  = flag.String("address", ":7654", "The server port")
	email    = flag.String("email", "", "ACME registration email")
)

func main() {
	flag.Parse()

	if *email == "" {
		grpclog.Fatalf("-email is required")
	}

	achmed, err := server.New(*email)
	if err != nil {
		grpclog.Fatalf("failed to created achemd server: %v", err)
	}

	lis, err := net.Listen("tcp", *address)
	if err != nil {
		grpclog.Fatalf("failed to listen: %v", err)
	}

	var opts []grpc.ServerOption
	if *tls {
		creds, err := credentials.NewServerTLSFromFile(*certFile, *keyFile)
		if err != nil {
			grpclog.Fatalf("Failed to generate credentials %v", err)
		}
		opts = []grpc.ServerOption{grpc.Creds(creds)}
	}

	grpcServer := grpc.NewServer(opts...)

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)

	achmed.Register(grpcServer)
	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			grpclog.Printf("Serve ended: %v", err)
		}
	}()

	<-ch
	signal.Stop(ch)

	grpcServer.GracefulStop()
}
