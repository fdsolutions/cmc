package model_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	. "github.com/fdsolutions/cmc/common/domain/model"
	"github.com/fdsolutions/cmc/samples"
)

var _ = Describe("Cer", func() {
	Describe(".FromRawPEM", func() {
		It("returns CERs from data PEM string", func() {
			certs, errRefs := FromRawPEM(samples.SinglePEMcert)
			Expect(errRefs).NotTo(BeNil())
			Expect(certs).To(HaveLen(1))
			Expect(certs[0]).To(BeAssignableToTypeOf(&CER{}))
		})
	})
})
