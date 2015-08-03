package certificate_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	. "github.com/fdsolutions/cmc-api/certificate"
	. "github.com/fdsolutions/cmc-api/certificate/samples"
)

var _ = Describe("Parser", func() {
	Describe(".Parse", func() {
		Context("With no PEM data certificate", func() {
			It("should return an error.", func() {
				certs, _ := Parse(EmptyPEMcert)
				Expect(certs).To(HaveLen(0))
			})
		})

		Context("With only one PEM data certificate", func() {
			It("should return only one certificate.", func() {
				certs, _ := Parse(SinglePEMcert)
				Expect(certs).To(HaveLen(1))
			})
		})

		Context("With multiple PEM data certificates", func() {
			It("should return all certificates from the PEM data parsed", func() {
				certs, _ := Parse(MultiPEMcerts)
				Expect(certs).To(HaveLen(4))
			})
		})

		Context("With one certificate well formatted PEM data certificate", func() {
			It("should return the certificate ignoring the other parts of the PEM data", func() {
				certs, _ := Parse(PEMcertWithSomeWrongCert)
				Expect(certs).To(HaveLen(1))
			})
		})
	})
})
