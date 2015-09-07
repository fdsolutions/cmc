package model

import (
	"crypto/x509"
	"fmt"
	"math/big"
	"strings"
)

// Info holds name and value of a single field
type Info map[string]interface{}

type certInfoGetter interface {
	GetVersion() int
	GetSerialNumber() string
	//signature
	GetSignature() string
	GetSignatureAlgorithm() string
	//Issuer info
	/*	GetIssuerInfo() Info
		GetIssuerCountry() string
		GetIssuerState() string
		GetIssuerLocality() string
		GetIssuerOrganization() string
		GetIssuerOrganizationUnit() string
		GetIssuerCommonName() string
		GetIssuerEmailAdress() string
		GetValidity()
		GetValidityNotBefore() string
		GetValidityNotAfter() string
		// subject info
		GetSubject() Info
		GetSubjectCountry() string
		GetSubjectState() string
		GetSubjectLocality() string
		GetSubjectOrganization() string
		GetSubjectOrganizationUnit() string
		GetSubjectCommonName() string
		GetSubjectEmailAdress() string
		// public key info
		GetPublicKey() Info
		GetPublicKeyInfoAlgorithm() string
		GetPublicKeyInfoSize() string
		GetPublicKeyInfoModulus() string
		GetExtensions() Info
		GetExtensionAutorityKeyIdentifier() string
		GetExtensionIssuerAltNames() string*/
}

type certInfoSetter interface {
	SetVersion(int)
	SetSerialNumber(*big.Int)
	//signature
	SetSignature([]byte)
	SetSignatureAlgorithm(x509.SignatureAlgorithm)
	//Issuer info
	/*	SetIssuerCountry(string)
		SetIssuerState(string)
		SetIssuerLocality(string)
		SetIssuerOrganization(string)
		SetIssuerOrganizationUnit(string)
		SetIssuerCommonName(string)
		SetIssuerEmailAdress(string)
		//validity
		SetValidityNotBefore(string)
		SetValidityNotAfter(string)
		// subject info
		SetSubjectCountry(string)
		SetSubjectState(string)
		SetSubjectLocality(string)
		SetSubjectOrganization(string)
		SetSubjectOrganizationUnit(string)
		SetSubjectCommonName(string)
		SetSubjectEmailAdress(string)
		// public key info
		SetPublicKeyInfoAlgorithm(string)
		SetPublicKeyInfoSize(string)
		SetPublicKeyInfoModulus(string)
		//extensions
		SetExtensionAutorityKeyIdentifier(string)
		SetExtensionIssuerAltNames(string)*/
}

const (
	firstField int = iota
	version
	serialNumber
	signature
	signatureAlgorithm

	issuer
	issuerCountry
	issuerState
	issuerLocality
	issuerOrganization
	issuerOrganizationUnit
	issuerCommonName
	issuerEmailAdress

	validity
	validityNotBefore
	validityNotAfter

	subject
	subjectCountry
	subjectState
	subjectLocality
	subjectOrganization
	subjectOrganizationUnit
	subjectCommonName
	subjectEmailAdress

	publicKey
	publicKeyInfoAlgorithm
	publicKeyInfoSize
	publicKeyInfoModulus

	extensions
	extensionAutorityKeyIdentifier
	extensionIssuerAltNames
	lastField
)

var certFieldNames = [...]string{
	version:            "version",
	serialNumber:       "serial number",
	signature:          "signature",
	signatureAlgorithm: "signature algorithm",

	issuer:                 "issuer",
	issuerCountry:          "country",
	issuerState:            "state",
	issuerLocality:         "locality",
	issuerOrganization:     "organization",
	issuerOrganizationUnit: "organization unit",
	issuerCommonName:       "common name",
	issuerEmailAdress:      "CA/email address",

	validity:          "validity",
	validityNotBefore: "Valid from",
	validityNotAfter:  "valid till",

	subject:                 "subject",
	subjectCountry:          "country",
	subjectState:            "state",
	subjectLocality:         "locality",
	subjectOrganization:     "organization",
	subjectOrganizationUnit: "organization unit",
	subjectCommonName:       "common name",
	subjectEmailAdress:      "CA/email address",

	publicKey:              "public key",
	publicKeyInfoAlgorithm: "algorithm",
	publicKeyInfoSize:      "size (bit)",
	publicKeyInfoModulus:   "modulus",

	extensions:                     "extensions",
	extensionAutorityKeyIdentifier: "authority key identifier",
	extensionIssuerAltNames:        "Subject Alternative Name (SAN)",
}

var signatureAlgorithmNames = [...]string{
	x509.UnknownSignatureAlgorithm: "Unknown Signature Algorithm",
	x509.MD2WithRSA:                "MD2 With RSA",
	x509.MD5WithRSA:                "MD5 With RSA",
	x509.SHA1WithRSA:               "SHA1 With RSA",
	x509.SHA256WithRSA:             "SHA256 With RSA",
	x509.SHA384WithRSA:             "SHA384 With RSA",
	x509.SHA512WithRSA:             "SHA512 With RSA",
	x509.DSAWithSHA1:               "DSA With SHA1",
	x509.DSAWithSHA256:             "DSA With SHA256",
	x509.ECDSAWithSHA1:             "ECDS AWith SHA1",
	x509.ECDSAWithSHA256:           "ECDSA With SHA256",
	x509.ECDSAWithSHA384:           "ECDSA With SHA384",
	x509.ECDSAWithSHA512:           "ECDSA With SHA512",
}

type CertInfo interface {
	certInfoGetter
	certInfoSetter
}

type certInfo struct {
	raw                []byte
	version            int
	serialNumber       string
	signature          string
	signatureAlgorithm string

	// issuer
	issuerCountry          string
	issuerState            string
	issuerLocality         string
	issuerOrganization     string
	issuerOrganizationUnit string
	issuerCommonName       string
	issuerEmailAdress      string

	// validity
	validityNotBefore string
	validityNotAfter  string

	// subject
	subjectCountry          string
	subjectState            string
	subjectLocality         string
	subjectOrganization     string
	subjectOrganizationUnit string
	subjectCommonName       string
	subjectEmailAdress      string

	// publicKey
	publicKeyInfoAlgorithm string
	publicKeyInfoSize      string
	publicKeyInfoModulus   string

	// extensions
	extensionAutorityKeyIdentifier string
	extensionIssuerAltNames        string
}

func NewCertInfo() CertInfo {
	return &certInfo{}
}

func (info *certInfo) SetVersion(v int) {
	info.version = v
}

func (info *certInfo) GetVersion() int {
	return info.version
}

func (info *certInfo) SetSerialNumber(sn *big.Int) {
	info.serialNumber = fmt.Sprintf("%s", sn)
}

func (info *certInfo) GetSerialNumber() string {
	return info.serialNumber
}

func (info *certInfo) SetSignature(s []byte) {
	//info.signature = hex.EncodeToString(s)
	info.signature = strings.TrimSpace(fmt.Sprintf("% x\n", s))
}

func (info *certInfo) GetSignature() string {
	return info.signature
}

func (info *certInfo) SetSignatureAlgorithm(sa x509.SignatureAlgorithm) {
	info.signatureAlgorithm = signatureAlgorithmNames[sa]
}

func (info *certInfo) GetSignatureAlgorithm() string {
	return info.signatureAlgorithm
}
