package model_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	. "github.com/fdsolutions/cmc/common/domain/model"
	"github.com/fdsolutions/cmc/samples"
)

var (
	certs   []CER
	errRefs ErrorRef
	cer     CER
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
			It("returns the version number", func() {
				info, _ := cer.GetInfos()
				Expect(info.GetVersion()).To(Equal(3))
			})
		})
	})
})
