package certificate_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

func TestCertificate(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Certificate Suite")
}
