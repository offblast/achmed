package server

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"rsc.io/letsencrypt"

	"github.com/offblast/achmed/proto"
)

type AchmedServer struct {
	m *letsencrypt.Manager
}

func New(email string) (*AchmedServer, error) {
	m := new(letsencrypt.Manager)
	if err := m.CacheFile("letsencrypt.cache"); err != nil {
		return nil, err
	}

	if !m.Registered() {
		if err := m.Register(email, nil); err != nil {
			return nil, err
		}
	}

	return &AchmedServer{m}, nil
}

func (a *AchmedServer) GetCertificate(ctx context.Context, clientHello *proto.ClientHelloInfo) (*proto.Certificate, error) {
	chi := proto.ProtoToClientHelloInfo(clientHello)
	cert, err := a.m.GetCertificate(chi)
	if err != nil {
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
