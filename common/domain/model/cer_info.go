package model

import (
	"fmt"
	"math/big"
)

// Info holds name and value of a single field
type Info map[string]interface{}

type certInfoGetter interface {
	GetVersion() int
	GetSerialNumber() string
	//signature
	/*	GetSignature() string
		GetSignatureAlgorithm() string
		//Issuer info
		GetIssuerInfo() Info
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
	/*	SetSignature(string)
		SetSignatureAlgorithm(string)
		//Issuer info
		SetIssuerCountry(string)
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

type CertInfo interface {
	certInfoGetter
	certInfoSetter
}

type certInfo struct {
	raw                []byte
	version            int
	serialNumber       string
	signatureAlgorithm string
	Signature          string

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
