package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/coreos/etcd/clientv3"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/crypto/openpgp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/offblast/achmed/cache"
	"github.com/offblast/achmed/server"
)

var (
	// achmed configuration
	address    = flag.String("address", ":7654", "The server port")
	cachetype  = flag.String("cache", "", "Certificate cache type (one of: \"\", memory, directory, etcd)")
	cryptcache = flag.Bool("cryptcache", false, "GPG encrypt certificates in the cache")
	cryptsec   = flag.String("cryptsec", "", "GPG secring for decryption")
	cryptpub   = flag.String("cryptpub", "", "GPG pubring for encryption")

	certdir  = flag.String("cachedir", "", "Directory for certificate cache")
	etcdaddr = flag.String("etcd", "http://127.0.0.1:2379", "Address of etcd for certificate cache")

	// grpc tls configuration
	tls     = flag.Bool("grpc-tls", false, "Connection uses TLS if true, else plain TCP")
	tlscert = flag.String("grpc-cert", "", "The TLS cert file")
	tlskey  = flag.String("grpc-key", "", "The TLS key file")

	// acme configuration
	email     = flag.String("acme-email", "", "ACME registration email")
	directory = flag.String("acme-directory", acme.LetsEncryptURL, "ACME server directory")
	key       = flag.String("acme-key", "acme.key", "ACME private key")
)

func checkOptions() {
	if *address == "" {
		log.Fatalf("-address is required")
	}

	if *cryptcache {
		if *cachetype == "" {
			log.Fatalf("-cache=\"\" is invalid with -cryptcache=true")
		}
		if *cryptsec == "" {
			log.Fatalf("-cryptsec is required with -cryptcache")
		}
		if *cryptpub == "" {
			log.Fatalf("-cryptpub is required with -cryptcache")
		}
	}

	if *cachetype == "directory" && *certdir == "" {
		log.Fatalf("-cachedir is required with -cache=directory")
	}

	if *cachetype == "etcd" && *etcdaddr == "" {
		log.Fatalf("-etcd is required with -cache=etcd")
	}

	if *tls {
		if *tlscert == "" {
			log.Fatalf("-grpc-cert is required with -grpc-tls")
		}
		if *tlskey == "" {
			log.Fatalf("-grpc-key is required with -grpc-tls")
		}
	}

	if *email == "" {
		log.Fatalf("-acme-email is required")
	}

	if *directory == "" {
		log.Fatalf("-acme-directory is required")
	}

	if *key == "" {
		log.Fatalf("-acme-key is required")
	}
}

func readKeyring(file string) (openpgp.EntityList, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	ent, err := openpgp.ReadArmoredKeyRing(f)
	if err != nil {
		return nil, err
	}

	return ent, nil
}

func getCache() autocert.Cache {
	var certcache autocert.Cache

	switch *cachetype {
	case "":
		certcache = nil
	case "memory":
		certcache = cache.NewMemCache()
	case "directory":
		certcache = autocert.DirCache(*certdir)
	case "etcd":
		etcdClient, err := clientv3.New(clientv3.Config{
			Endpoints:   strings.Split(*etcdaddr, ","),
			DialTimeout: 5 * time.Second,
		})

		if err != nil {
			log.Fatalf("Failed to create etcd client: %v", err)
		}
		certcache = &cache.EtcdCache{etcdClient}
	default:
		log.Fatalf("Unknown cache type %q", *cachetype)
	}

	if *cryptcache {
		pubring, err := readKeyring(*cryptpub)
		if err != nil {
			log.Fatalf("Failed to read GPG pubring %q: %v", *cryptpub, err)
		}

		secring, err := readKeyring(*cryptsec)
		if err != nil {
			log.Fatalf("Failed to read GPG secring %q: %v", *cryptsec, err)
		}

		certcache = &cache.CryptCache{
			Plaintext: certcache,
			Encrypt:   pubring,
			Decrypt:   secring,
		}
	}

	return certcache
}

func main() {
	flag.Parse()

	checkOptions()

	certcache := getCache()

	eckey, err := loadKey(*key)
	if err != nil {
		log.Fatalf("Can't read ACME key %q: %v", *key, err)
	}

	client := &acme.Client{
		Key:          eckey,
		DirectoryURL: *directory,
	}

	achmed, err := server.New(*email, certcache, client, nil)
	if err != nil {
		log.Fatalf("Failed to created achemd server: %v", err)
	}

	lis, err := net.Listen("tcp", *address)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	var opts []grpc.ServerOption
	if *tls {
		creds, err := credentials.NewServerTLSFromFile(*tlscert, *tlskey)
		if err != nil {
			log.Fatalf("Failed to generate credentials %v", err)
		}
		opts = []grpc.ServerOption{grpc.Creds(creds)}
	}

	grpcServer := grpc.NewServer(opts...)

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)

	achmed.Register(grpcServer)
	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			log.Printf("Serve ended: %v", err)
		}
	}()

	<-ch
	signal.Stop(ch)

	grpcServer.GracefulStop()
}

func loadKey(file string) (*ecdsa.PrivateKey, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}

	defer f.Close()

	b, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}

	return unmarshalKey(string(b))
}

// pinched from https://github.com/rsc/letsencrypt/blob/master/lets.go.
func unmarshalKey(text string) (*ecdsa.PrivateKey, error) {
	b, _ := pem.Decode([]byte(text))
	if b == nil {
		return nil, fmt.Errorf("unmarshalKey: missing key")
	}
	if b.Type != "EC PRIVATE KEY" {
		return nil, fmt.Errorf("unmarshalKey: found %q, not %q", b.Type, "EC PRIVATE KEY")
	}
	k, err := x509.ParseECPrivateKey(b.Bytes)
	if err != nil {
		return nil, fmt.Errorf("unmarshalKey: %v", err)
	}
	return k, nil
}
