package certificate_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	. "github.com/fdsolutions/cmc-api/certificate"
	. "github.com/fdsolutions/cmc-api/certificate/samples"
)

var _ = Describe("Crt", func() {
	Describe(".FromRawPEM", func() {
		It("returns CRTs from data PEM string", func() {
			crts, errRefs := FromRawPEM(SinglePEMcert)
			Expect(errRefs).NotTo(BeNil())
			Expect(crts).To(HaveLen(1))
			Expect(crts[0]).To(BeAssignableToTypeOf(&Crt{}))
		})
	})
})
