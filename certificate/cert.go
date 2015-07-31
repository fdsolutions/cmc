package certificate

import (
	"crypto/x509"
)

type detailer interface {
	GetRawPEM() string
	GetVersion() string
}

type Cert struct {
	*x509.Certificate
	//detailer
}

func FromRawPEM(data string) []*Cert {
	return nil
}
