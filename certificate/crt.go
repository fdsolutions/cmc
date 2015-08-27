package certificate

import (
	"crypto/x509"
	"fmt"
)

type detailer interface {
	GetRawPEM() string
	GetVersion() string
}

// Crt wraps all information relative to certificate
type Crt struct {
	x509.Certificate
}

// FromRawPEM returns all crertificates referenced in the PEM data string
func FromRawPEM(data string) (crts []*Crt, errRefs ErrorRef) {
	x509certs, errRefs := Parse(data)
	crts = make([]*Crt, len(x509certs))
	for i, c := range x509certs {
		crts[i] = &Crt{*c}
	}
	return
}
