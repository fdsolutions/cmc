package model

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// Info holds name and value of a single field
type Info map[string]interface{}

type certInfoGetter interface {
	GetRaw() string
	GetVersion() int
	GetSerialNumber() string
	//signature
	GetSignature() string
	GetSignatureAlgorithm() string
	//Issuer info
	GetIssuerInfo() Info
	GetIssuerCountry() string
	GetIssuerState() string
	GetIssuerLocality() string
	GetIssuerOrganization() string
	GetIssuerOrganizationUnit() string
	GetIssuerCommonName() string
	GetIssuerStreetAddress() string
	//validity
	GetValidityInfo() Info
	GetValidityNotBefore() string
	GetValidityNotAfter() string
	// subject info
	GetSubjectInfo() Info
	GetSubjectCountry() string
	GetSubjectState() string
	GetSubjectLocality() string
	GetSubjectOrganization() string
	GetSubjectOrganizationUnit() string
	GetSubjectCommonName() string
	GetSubjectStreetAddress() string
	// public key info
	/*	GetPublicKey() Info
		GetPublicKeyInfoAlgorithm() string
		GetPublicKeyInfoSize() string
		GetPublicKeyInfoModulus() string
		GetExtensions() Info
		GetExtensionAutorityKeyIdentifier() string
		GetExtensionIssuerAltNames() string*/
}

type certInfoSetter interface {
	SetRaw([]byte)
	SetVersion(int)
	SetSerialNumber(*big.Int)
	//signature
	SetSignature([]byte)
	SetSignatureAlgorithm(x509.SignatureAlgorithm)
	//Issuer info
	SetIssuer(pkix.Name)
	setIssuerCountry([]string)
	setIssuerState([]string)
	setIssuerLocality([]string)
	setIssuerOrganization([]string)
	setIssuerOrganizationUnit([]string)
	setIssuerCommonName(string)
	setIssuerStreetAddress([]string)
	//validity
	SetValidityNotBefore(t time.Time)
	SetValidityNotAfter(t time.Time)
	// subject info
	SetSubjectInfo(pkix.Name)
	setSubjectCountry([]string)
	setSubjectState([]string)
	setSubjectLocality([]string)
	setSubjectOrganization([]string)
	setSubjectOrganizationUnit([]string)
	setSubjectCommonName(string)
	setSubjectStreetAddress([]string)
	// public key info
	/*	SetPublicKeyInfoAlgorithm(string)
		SetPublicKeyInfoSize(string)
		SetPublicKeyInfoModulus(string)
		//extensions
		SetExtensionAutorityKeyIdentifier(string)
		SetExtensionIssuerAltNames(string)*/
}

const (
	delim string = ", "

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
	issuerStreetAddress

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
	subjectStreetAddress

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
	signatureAlgorithm: "signature_algorithm",

	issuer:                 "issuer",
	issuerCountry:          "country",
	issuerState:            "state",
	issuerLocality:         "locality",
	issuerOrganization:     "organization",
	issuerOrganizationUnit: "organization_unit",
	issuerCommonName:       "common_name",
	issuerStreetAddress:    "street_address",

	validity:          "validity",
	validityNotBefore: "valid_from",
	validityNotAfter:  "valid_till",

	subject:                 "subject",
	subjectCountry:          "country",
	subjectState:            "state",
	subjectLocality:         "locality",
	subjectOrganization:     "organization",
	subjectOrganizationUnit: "organization unit",
	subjectCommonName:       "common_name",
	subjectStreetAddress:    "street_address",

	publicKey:              "public_key",
	publicKeyInfoAlgorithm: "algorithm",
	publicKeyInfoSize:      "size_in_bits",
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
	raw                string
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
	issuerStreetAddress    string

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
	subjectStreetAddress    string

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

func (info *certInfo) GetRaw() string {
	return info.raw
}
func (info *certInfo) SetRaw(raw []byte) {
	//TODO: Find a way to report errors when encoding fails.
	var buff bytes.Buffer
	b := pem.Block{"CERTIFICATE", map[string]string{}, raw}

	pem.Encode(&buff, &b)
	info.raw = strings.TrimSpace(buff.String())
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

func (info *certInfo) GetIssuerInfo() Info {
	return Info{
		certFieldNames[issuer]: map[string]string{
			certFieldNames[issuerState]:            info.issuerState,
			certFieldNames[issuerLocality]:         info.issuerLocality,
			certFieldNames[issuerOrganization]:     info.issuerOrganization,
			certFieldNames[issuerOrganizationUnit]: info.issuerOrganizationUnit,
			certFieldNames[issuerCommonName]:       info.issuerCommonName,
			certFieldNames[issuerStreetAddress]:    info.issuerStreetAddress,
		},
	}
}
func (info *certInfo) SetIssuer(n pkix.Name) {
	info.setIssuerCountry(n.Country)
	info.setIssuerState(n.Province)
	info.setIssuerLocality(n.Locality)
	info.setIssuerOrganization(n.Organization)
	info.setIssuerOrganizationUnit(n.OrganizationalUnit)
	info.setIssuerCommonName(n.CommonName)
	info.setIssuerStreetAddress(n.StreetAddress)
}

func (info *certInfo) GetIssuerCountry() string {
	return info.issuerCountry
}
func (info *certInfo) setIssuerCountry(c []string) {
	info.issuerCountry = strings.Join(c, delim)
}

func (info *certInfo) GetIssuerState() string {
	return info.issuerState
}
func (info *certInfo) setIssuerState(s []string) {
	info.issuerState = strings.Join(s, delim)
}

func (info *certInfo) GetIssuerLocality() string {
	return info.issuerLocality
}
func (info *certInfo) setIssuerLocality(l []string) {
	info.issuerLocality = strings.Join(l, delim)
}

func (info *certInfo) GetIssuerOrganization() string {
	return info.issuerOrganization
}
func (info *certInfo) setIssuerOrganization(o []string) {
	info.issuerOrganization = strings.Join(o, delim)
}

func (info *certInfo) GetIssuerOrganizationUnit() string {
	return info.issuerOrganizationUnit
}
func (info *certInfo) setIssuerOrganizationUnit(ou []string) {
	info.issuerOrganizationUnit = strings.Join(ou, delim)
}

func (info *certInfo) GetIssuerCommonName() string {
	return info.issuerCommonName
}
func (info *certInfo) setIssuerCommonName(cn string) {
	info.issuerCommonName = cn
}

func (info *certInfo) GetIssuerStreetAddress() string {
	return info.issuerStreetAddress
}
func (info *certInfo) setIssuerStreetAddress(sa []string) {
	info.issuerStreetAddress = strings.Join(sa, delim)
}

func (info *certInfo) GetValidityInfo() Info {
	return Info{
		certFieldNames[validity]: map[string]string{
			certFieldNames[validityNotBefore]: info.validityNotBefore,
			certFieldNames[validityNotAfter]:  info.validityNotAfter,
		},
	}
}

func (info *certInfo) GetValidityNotBefore() string {
	return info.validityNotBefore
}
func (info *certInfo) SetValidityNotBefore(t time.Time) {
	info.validityNotBefore = t.String()
}

func (info *certInfo) GetValidityNotAfter() string {
	return info.validityNotAfter
}
func (info *certInfo) SetValidityNotAfter(t time.Time) {
	info.validityNotAfter = t.String()
}

func (info *certInfo) GetSubjectInfo() Info {
	return Info{
		certFieldNames[subject]: map[string]string{
			certFieldNames[subjectCountry]:          info.subjectCountry,
			certFieldNames[subjectState]:            info.subjectState,
			certFieldNames[subjectLocality]:         info.subjectLocality,
			certFieldNames[subjectOrganization]:     info.subjectOrganization,
			certFieldNames[subjectOrganizationUnit]: info.subjectOrganizationUnit,
			certFieldNames[subjectCommonName]:       info.subjectCommonName,
			certFieldNames[subjectStreetAddress]:    info.subjectStreetAddress,
		},
	}
}

func (info *certInfo) SetSubjectInfo(sj pkix.Name) {
	info.setSubjectCountry(sj.Country)
	info.setSubjectState(sj.Province)
	info.setSubjectLocality(sj.Locality)
	info.setSubjectOrganization(sj.Organization)
	info.setSubjectOrganizationUnit(sj.OrganizationalUnit)
	info.setSubjectCommonName(sj.CommonName)
	info.setSubjectStreetAddress(sj.StreetAddress)
}

func (info *certInfo) GetSubjectCountry() string {
	return info.subjectCountry
}
func (info *certInfo) setSubjectCountry(c []string) {
	info.subjectCountry = strings.Join(c, delim)
}

func (info *certInfo) GetSubjectState() string {
	return info.subjectState
}
func (info *certInfo) setSubjectState(s []string) {
	info.subjectCountry = strings.Join(s, delim)
}

func (info *certInfo) GetSubjectLocality() string {
	return info.subjectLocality
}
func (info *certInfo) setSubjectLocality(l []string) {
	info.subjectLocality = strings.Join(l, delim)
}

func (info *certInfo) GetSubjectOrganization() string {
	return info.subjectOrganization
}
func (info *certInfo) setSubjectOrganization(o []string) {
	info.subjectOrganization = strings.Join(o, delim)
}

func (info *certInfo) GetSubjectOrganizationUnit() string {
	return info.subjectOrganizationUnit
}
func (info *certInfo) setSubjectOrganizationUnit(ou []string) {
	info.subjectOrganizationUnit = strings.Join(ou, delim)
}

func (info *certInfo) GetSubjectCommonName() string {
	return info.subjectCommonName
}
func (info *certInfo) setSubjectCommonName(cn string) {
	info.subjectCommonName = cn
}

func (info *certInfo) GetSubjectStreetAddress() string {
	return info.subjectStreetAddress
}
func (info *certInfo) setSubjectStreetAddress(sa []string) {
	info.subjectStreetAddress = strings.Join(sa, delim)
}
