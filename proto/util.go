package proto

import (
	"crypto/tls"
)

func ClientHelloInfoToProto(clientHello *tls.ClientHelloInfo) *ClientHelloInfo {
	chi := ClientHelloInfo{
		Ciphersuites:    make([]uint32, len(clientHello.CipherSuites)),
		Servername:      clientHello.ServerName,
		Supportedcurves: make([]uint32, len(clientHello.SupportedCurves)),
		Supportedpoints: []byte(clientHello.SupportedPoints),
	}

	for i, cs := range clientHello.CipherSuites {
		chi.Ciphersuites[i] = uint32(cs)
	}

	for i, sc := range clientHello.SupportedCurves {
		chi.Supportedcurves[i] = uint32(sc)
	}

	return &chi
}

func ProtoToClientHelloInfo(clientHello *ClientHelloInfo) *tls.ClientHelloInfo {
	chi := tls.ClientHelloInfo{
		CipherSuites:    make([]uint16, len(clientHello.Ciphersuites)),
		ServerName:      clientHello.Servername,
		SupportedCurves: make([]tls.CurveID, len(clientHello.Supportedcurves)),
		SupportedPoints: []uint8(clientHello.Supportedpoints),
	}

	for i, cs := range clientHello.Ciphersuites {
		chi.CipherSuites[i] = uint16(cs)
	}

	for i, sc := range clientHello.Supportedcurves {
		chi.SupportedCurves[i] = tls.CurveID(sc)
	}

	return &chi
}
