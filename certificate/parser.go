package certificate

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// Parse extract all certificates from a content that list all PEM data string
func Parse(PEMdata string) (certs []*x509.Certificate, e error) {
	errRefs := make(map[int]error)
	_, blocks, _ := decodePEMdataInBlocks(0, []byte{}, []byte(PEMdata), errRefs)
	fmt.Printf("%#v", errRefs)
	certs, _ = x509.ParseCertificates(blocks)
	return
}

func decodePEMdataInBlocks(idx int, blocks, rest []byte, errRefs map[int]error) (nextIdx int, accBlocks, next []byte) {
	var block *pem.Block
	// Keep the state if for some reasons there is nothing to decode
	// or the decoding failed for one block of content.
	nextIdx, accBlocks, next = idx, blocks, nil

	if len(rest) == 0 { // No more PEM data to decode
		return
	}

	if block, next = pem.Decode(rest); block == nil {
		errRefs[idx] = fmt.Errorf("Error: Invalid PEM content at position %v", idx)
		return
	}
	accBlocks = append(blocks, block.Bytes...)
	nextIdx = idx + 1

	return decodePEMdataInBlocks(nextIdx, accBlocks, next, errRefs)
}
