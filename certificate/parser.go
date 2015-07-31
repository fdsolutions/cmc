package certificate

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
)

func Parse(PEMdata string) (certs []*x509.Certificate, err error) {
	var blocks []byte

	rest := []byte(PEMdata)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)

		if block == nil {
			err = errors.New("ParseError: Invalid PEM content.")
			break
		}
		blocks = append(blocks, block.Bytes...)
		if len(rest) == 0 {
			break
		}
	}

	certs, err = x509.ParseCertificates(blocks)
	if err != nil {
		err = errors.New("ParseError: Unable to get certificate form PEM Blocks.")
		return
	}

	return
}
