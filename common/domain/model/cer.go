package model

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

// CER represent a signed certificate
type CER struct {
	x509.Certificate
}

func (cer CER) GetInfos() (ci CertInfo, err error) {
	info := NewCertInfo()

	v := cer.Certificate.Version
	info.SetVersion(v)

	sn := cer.Certificate.SerialNumber
	info.SetSerialNumber(sn)

	s := cer.Certificate.Signature
	info.SetSignature(s)

	sa := cer.Certificate.SignatureAlgorithm
	info.SetSignatureAlgorithm(sa)

	u := cer.Certificate.Issuer
	info.SetIssuer(u)

	tBefore := cer.Certificate.NotBefore
	info.SetValidityNotBefore(tBefore)
	tAfter := cer.Certificate.NotAfter
	info.SetValidityNotAfter(tAfter)

	ci = info
	return
}

// FromRawPEM returns all crertificates referenced in the PEM data string
func FromRawPEM(data string) (certs []CER, errRefs ErrorRef) {
	x509certs, errRefs := parse(data)
	certs = make([]CER, len(x509certs))
	for i, c := range x509certs {
		certs[i] = CER{*c}
	}
	return
}

// Parse extract all certificates from a content that list all PEM data string
func parse(PEMdata string) (certs []*x509.Certificate, errRefs ErrorRef) {
	errRefs = NewErrorRef()
	_, blocks, _ := decodePEMdataInBlocks(0, []byte{}, []byte(PEMdata), errRefs)
	certs, _ = x509.ParseCertificates(blocks)
	return
}

func decodePEMdataInBlocks(idx int, blocks, rest []byte, errRefs ErrorRef) (nextIdx int, accBlocks, next []byte) {
	var block *pem.Block
	// Keep the state if for some reasons there is nothing to decode
	// or the decoding failed for one block of content.
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
