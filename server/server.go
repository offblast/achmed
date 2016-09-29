package server

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/context"
	"google.golang.org/grpc"

	"github.com/offblast/achmed/proto"
)

type AchmedServer struct {
	m *autocert.Manager
}

// New creates a new AchmedServer.
//
// See https://godoc.org/golang.org/x/crypto/acme/autocert#Manager for argument details.
func New(email string, cache autocert.Cache, client *acme.Client, hostpolicy autocert.HostPolicy) (*AchmedServer, error) {
	m := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      cache,
		HostPolicy: hostpolicy,
		Client:     client,
		Email:      email,
	}

	return &AchmedServer{m}, nil
}

func (a *AchmedServer) GetCertificate(ctx context.Context, clientHello *proto.ClientHelloInfo) (*proto.Certificate, error) {
	chi := proto.ProtoToClientHelloInfo(clientHello)
	cert, err := a.m.GetCertificate(chi)
	if err != nil {
		log.Printf("achmed: failed to get certificate for %q: %v", chi.ServerName, err)
		return nil, err
	}

	var pembuf bytes.Buffer

	var pkey *pem.Block

	switch t := cert.PrivateKey.(type) {
	case *rsa.PrivateKey:
		pkey = &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(t)}
	case *ecdsa.PrivateKey:
		pkeyb, err := x509.MarshalECPrivateKey(t)
		if err != nil {
			return nil, err
		}

		pkey = &pem.Block{Type: "EC PRIVATE KEY", Bytes: pkeyb}
	default:
		return nil, x509.ErrUnsupportedAlgorithm
	}

	if err := pem.Encode(&pembuf, pkey); err != nil {
		return nil, err
	}

	for _, b := range cert.Certificate {
		pb := &pem.Block{Type: "CERTIFICATE", Bytes: b}
		if err := pem.Encode(&pembuf, pb); err != nil {
			return nil, err
		}
	}

	return &proto.Certificate{Pem: pembuf.Bytes()}, nil
}

func (a *AchmedServer) Register(serv *grpc.Server) {
	proto.RegisterAchmedServer(serv, a)
}
