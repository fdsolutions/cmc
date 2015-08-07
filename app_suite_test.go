package main

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

func TestCmcApi(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "CmcApi Suite")
}
