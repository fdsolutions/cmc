package certificate

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// ErrorRef is used to keep track of PEM data that failed to be parsed
type ErrorRef map[int]error

// NewErrorRef is the constructor
func NewErrorRef() ErrorRef {
	return ErrorRef{}
}

// Add save the error happened when parse a PEM in 'idx' position
func (er ErrorRef) Add(idx int, err error) {
	er[idx] = err
}

// Parse extract all certificates from a content that list all PEM data string
func Parse(PEMdata string) (certs []*x509.Certificate, errRefs ErrorRef) {
	errRefs = NewErrorRef()
	_, blocks, _ := decodePEMdataInBlocks(0, []byte{}, []byte(PEMdata), errRefs)
	certs, _ = x509.ParseCertificates(blocks)
	return
}

func decodePEMdataInBlocks(idx int, blocks, rest []byte, errRefs ErrorRef) (nextIdx int, accBlocks, next []byte) {
	var block *pem.Block
	// preset return values
	nextIdx, accBlocks, next = idx, blocks, nil

	if len(rest) == 0 { // No more PEM data to decode
		return
	}

	if block, next = pem.Decode(rest); block == nil {
		errRefs.Add(idx, fmt.Errorf("Error: Invalid PEM content at position %v", idx))
		return
	}

	accBlocks = append(blocks, block.Bytes...)
	nextIdx = idx + 1

	return decodePEMdataInBlocks(nextIdx, accBlocks, next, errRefs)
}
