package achmed

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/context"
	"google.golang.org/grpc"

	"github.com/offblast/achmed/proto"
)

type Client struct {
	c  *grpc.ClientConn
	ac proto.AchmedClient
}

func New(address string, opts ...grpc.DialOption) (*Client, error) {
	cc, err := grpc.Dial(address, opts...)
	if err != nil {
		return nil, err
	}

	ac := proto.NewAchmedClient(cc)

	return &Client{cc, ac}, nil
}

func (c *Client) Close() error {
	return c.c.Close()
}

func (c *Client) GetCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	chi := proto.ClientHelloInfoToProto(clientHello)
	ctx := context.Background()

	certmsg, err := c.ac.GetCertificate(ctx, chi)
	if err != nil {
		return nil, err
	}

	// below is yanked from golang.org/x/crypto/acme/autocert/autocert.go

	// private
	priv, pub := pem.Decode(certmsg.Pem)
	if priv == nil || !strings.Contains(priv.Type, "PRIVATE") {
		return nil, fmt.Errorf("achmed: invalid private key")
	}
	privKey, err := parsePrivateKey(priv.Bytes)
	if err != nil {
		return nil, err
	}

	// public
	var pubDER []byte
	for len(pub) > 0 {
		var b *pem.Block
		b, pub = pem.Decode(pub)
		if b == nil {
			break
		}
		pubDER = append(pubDER, b.Bytes...)
	}

	// parse public part(s) and verify the leaf is not expired
	// and corresponds to the private key
	x509Cert, err := x509.ParseCertificates(pubDER)
	if len(x509Cert) == 0 {
		return nil, errors.New("acme/autocert: no public key found in cache")
	}
	leaf := x509Cert[0]
	now := time.Now()
	if now.Before(leaf.NotBefore) {
		return nil, errors.New("acme/autocert: certificate is not valid yet")
	}

	// only check if this is not a challenge.
	if !strings.HasSuffix(clientHello.ServerName, ".acme.invalid") && now.After(leaf.NotAfter) {
		return nil, errors.New("acme/autocert: expired certificate")
	}

	if !domainMatch(leaf, clientHello.ServerName) {
		return nil, errors.New("acme/autocert: certificate does not match domain name")
	}
	switch pub := leaf.PublicKey.(type) {
	case *rsa.PublicKey:
		prv, ok := privKey.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("acme/autocert: private key type does not match public key type")
		}
		if pub.N.Cmp(prv.N) != 0 {
			return nil, errors.New("acme/autocert: private key does not match public key")
		}
	case *ecdsa.PublicKey:
		prv, ok := privKey.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("acme/autocert: private key type does not match public key type")
		}
		if pub.X.Cmp(prv.X) != 0 || pub.Y.Cmp(prv.Y) != 0 {
			return nil, errors.New("acme/autocert: private key does not match public key")
		}
	default:
		return nil, errors.New("acme/autocert: unknown public key algorithm")
	}

	tlscert := &tls.Certificate{
		Certificate: make([][]byte, len(x509Cert)),
		PrivateKey:  privKey,
		Leaf:        leaf,
	}
	for i, crt := range x509Cert {
		tlscert.Certificate[i] = crt.Raw
	}
	return tlscert, nil
}

// Attempt to parse the given private key DER block. OpenSSL 0.9.8 generates
// PKCS#1 private keys by default, while OpenSSL 1.0.0 generates PKCS#8 keys.
// OpenSSL ecparam generates SEC1 EC private keys for ECDSA. We try all three.
//
// Copied from crypto/tls/tls.go.
func parsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			return key, nil
		default:
			return nil, errors.New("acme/autocert: found unknown private key type in PKCS#8 wrapping")
		}
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}

	return nil, errors.New("acme/autocert: failed to parse private key")
}

// domainMatch matches cert against the specified domain name.
// It doesn't support wildcard.
//
// Copied from golang.org/x/crypto/acme/autocert/autocert.go.
func domainMatch(cert *x509.Certificate, name string) bool {
	if cert.Subject.CommonName == name {
		return true
	}
	sort.Strings(cert.DNSNames)
	i := sort.SearchStrings(cert.DNSNames, name)
	return i < len(cert.DNSNames) && cert.DNSNames[i] == name
}
