package apivalidations

import (
	"fmt"

	"github.com/xperimental/crdunitvalidate"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = Describe("", func() {
	DescribeTable("Verifying declarative API validations", func(crFile string, assert func(string, error)) {
		crYaml, err := tomlContent.ReadFile(crFile)
		if err != nil {
			Fail(fmt.Sprintf("Error reading the file %q with exp config: %v", crFile, err))
		}

		cr, err := crdunitvalidate.LoadYAML(crYaml)
		if err != nil {
			Fail(fmt.Sprintf("Error loading resource from YAML: %s", err))
		}

		validator, err := crdunitvalidate.NewValidator("../../bundle/manifests/observability.openshift.io_clusterlogforwarders.yaml")
		if err != nil {
			Fail(fmt.Sprintf("Error creating validator: %v", err))
		}

		err = validator.Validate(cr)
		assert("", err)
	},
		Entry("LOG-5788: for multilineException filter should not fail", "log5788_mulitiline_ex_filter.yaml", func(out string, err error) {
			Expect(err).ToNot(HaveOccurred())
		}),
		Entry("LOG-5793: for lokiStack bearer token from SA should not fail", "log5793_bearer_token_from_sa.yaml", func(out string, err error) {
			Expect(err).ToNot(HaveOccurred())
		}),
		Entry("should fail with invalid name", "invalid_name.yaml", func(out string, err error) {
			Expect(err.Error()).To(MatchRegexp("Name.*valid DNS1035"))
		}),
	)
})
