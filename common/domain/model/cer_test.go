package model_test

import (
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	. "github.com/fdsolutions/cmc/common/domain/model"
	"github.com/fdsolutions/cmc/samples"
)

var (
	certs   []CER
	errRefs ErrorRef
	cer     CER
	info    CertInfo
)

var _ = Describe("Cer", func() {
	BeforeEach(func() {
		certs, errRefs = FromRawPEM(samples.SinglePEMcert)
		cer = certs[0]
	})

	Describe(".FromRawPEM", func() {
		It("returns CERs from data PEM string", func() {
			Expect(errRefs).NotTo(BeNil())
			Expect(certs).To(HaveLen(1))
			Expect(cer).To(BeAssignableToTypeOf(CER{}))
		})
	})
	Describe("#GetInfos", func() {
		Context("With a valid CER", func() {
			BeforeEach(func() {
				info, _ = cer.GetInfos()
			})
			It("contains the RAW certificate as PEM", func() {
				expectedRaw := strings.TrimSpace(samples.SinglePEMcert)
				Expect(info.GetRaw()).To(Equal(expectedRaw))
			})
			It("contains the version number", func() {
				Expect(info.GetVersion()).To(Equal(3))
			})
			It("contains the serial number", func() {
				Expect(info.GetSerialNumber()).To(Equal("1404354960355712309"))
			})
			It("contains signature and signature algorithm", func() {
				expectedSig := `1f a4 58 1f 11 dd 70 6a 4c a4 51 37 a3 10 e8 16 73 fe 82 db ` +
					`81 08 76 a7 db 21 36 19 16 c9 d8 2c 3c 2f 0d 0c 9a e2 aa 1e 57 fd 45 27 98 7d dd ` +
					`c1 5d e2 a4 8f 5a 8e e9 35 4a c0 28 7e d0 77 59 93 6f 37 4d 96 72 ce 61 0e c9 c9 ` +
					`66 dd 41 85 61 ef 36 3f f8 83 16 df 82 79 0d cd a6 60 60 f8 6a 1a 54 2b 96 00 ` +
					`04 49 37 f2 9f 82 56 cb cb 26 32 81 c4 2a d1 28 1e 0e 1f 1d 44 a5 22 69 6d c7 41 ` +
					`2a 18 bd 3b dd 4e ea b3 c0 ae 02 5e ca f7 6f 9f dd 00 e6 3c b8 cb 86 fc 80 11 dc ` +
					`58 30 4d b6 75 76 da 16 46 f3 93 6b c8 58 89 4e 80 e3 be 56 b9 92 b2 10 77 30 ` +
					`9c 66 1e e7 bb b6 23 62 9b 32 07 0a 8c f9 e2 a1 c8 f8 43 38 18 b1 50 15 29 6d c8 ` +
					`c1 a3 a1 c8 4f af 3f 1b 22 52 4b d0 1d d3 b6 7e 88 c2 91 8f 23 83 bd 23 c4 cf a0 ` +
					`bb 9f 6d 3c 33 5b c3 75 21 ff 62 23 df 5d 05 81 31 ec 9c 64 0c c8`

				expectedSigAlg := `SHA1 With RSA`
				Expect(info.GetSignature()).To(Equal(expectedSig))
				Expect(info.GetSignatureAlgorithm()).To(Equal(expectedSigAlg))
			})
			It("contains Issuer info", func() {
				expectedInfo := Info{
					"issuer": map[string]string{
						"state":             "",
						"locality":          "",
						"organization":      "Google Inc",
						"organization_unit": "",
						"common_name":       "Google Internet Authority G2",
						"street_address":    "",
					},
				}
				Expect(info.GetIssuerInfo()).To(Equal(expectedInfo))
			})
			It("contains Validity info", func() {
				expectedInfo := Info{
					"validity": map[string]string{
						"valid_from": "2014-01-29 13:27:43 +0000 UTC",
						"valid_till": "2014-05-29 00:00:00 +0000 UTC",
					},
				}
				Expect(info.GetValidityInfo()).To(Equal(expectedInfo))
			})
			It("contains subject info", func() {
				expectedInfo := Info{
					"subject": map[string]string{
						"street_address":    "",
						"country":           "California",
						"state":             "",
						"locality":          "Mountain View",
						"organization":      "Google Inc",
						"organization unit": "",
						"common_name":       "mail.google.com",
					},
				}
				Expect(info.GetSubjectInfo()).To(Equal(expectedInfo))
			})
		})
	})
})
