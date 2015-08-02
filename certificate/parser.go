package certificate

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// Parse extract all certificates from a content that list all PEM data string
func Parse(PEMdata string) (certs []*x509.Certificate, e error) {
	_, blocks, _ := decodePEMdataInBlocks(0, []byte{}, []byte(PEMdata))
	certs, _ = x509.ParseCertificates(blocks)
	return
}

func decodePEMdataInBlocks(idx int, blocks, rest []byte) (nextIdx int, accBlocks, next []byte) {
	var block *pem.Block

	if len(rest) == 0 { // No more PEM data to decode
		return idx, blocks, nil
	}

	if block, next = pem.Decode(rest); next == nil {
		fmt.Printf("Error: Invalid PEM content at position %v", idx)
		return
	}

	accBlocks = append(blocks, block.Bytes...)
	nextIdx = idx + 1

	return decodePEMdataInBlocks(nextIdx, accBlocks, next)
}
