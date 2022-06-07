package servicemonitor_test

import (
	"github.com/ViaQ/logerr/v2/log"
	monitoringv1 "github.com/coreos/prometheus-operator/pkg/apis/monitoring/v1"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/openshift/cluster-logging-operator/internal/utils/comparators/servicemonitor"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("serviceMonitor#AreSame", func() {

	var (
		logger           = log.NewLogger("servicemonitor-test")
		current, desired *monitoringv1.ServiceMonitor
	)

	BeforeEach(func() {
		current = &monitoringv1.ServiceMonitor{
			ObjectMeta: metav1.ObjectMeta{
				Labels:      map[string]string{},
				Annotations: map[string]string{},
			},
			Spec: monitoringv1.ServiceMonitorSpec{
				Selector: metav1.LabelSelector{
					MatchLabels:      map[string]string{},
					MatchExpressions: []metav1.LabelSelectorRequirement{},
				},
				Endpoints:       []monitoringv1.Endpoint{},
				PodTargetLabels: []string{},
			},
		}
		desired = current.DeepCopy()

	})

	Context("when evaluating labels", func() {
		It("should recognize they are the same", func() {
			Expect(servicemonitor.AreSame(logger, current, desired)).To(BeTrue())
		})

		It("should recognize they are different", func() {
			desired.Labels["foo"] = "bar"
			Expect(servicemonitor.AreSame(logger, current, desired)).To(BeFalse())
		})
	})

	Context("when evaluating Annotations", func() {
		It("should recognize they are the same", func() {
			Expect(servicemonitor.AreSame(logger, current, desired)).To(BeTrue())
		})

		It("should recognize they are different", func() {
			desired.ObjectMeta.Annotations["foo"] = "bar"
			Expect(servicemonitor.AreSame(logger, current, desired)).To(BeFalse())
		})
	})

	Context("when evaluating ObjectMeta Labels", func() {
		It("should recognize they are the same", func() {
			Expect(servicemonitor.AreSame(logger, current, desired)).To(BeTrue())
		})

		It("should recognize they are the same", func() {
			desired.ObjectMeta.Labels["foo"] = "bar"
			Expect(servicemonitor.AreSame(logger, current, desired)).To(BeFalse())
		})
	})

	Context("when evaluating JobLabel", func() {
		It("should recognize they are the same", func() {
			Expect(servicemonitor.AreSame(logger, current, desired)).To(BeTrue())
		})

		It("should recognize they are different lengths", func() {
			desired.Spec.JobLabel = "foo"
			Expect(servicemonitor.AreSame(logger, current, desired)).To(BeFalse())
		})
	})

	Context("when evaluating MatchExpressions", func() {
		It("should recognize they are the same", func() {
			Expect(servicemonitor.AreSame(logger, current, desired)).To(BeTrue())
		})

		It("should recognize they are different content", func() {
			current.Spec.Selector.MatchExpressions = []metav1.LabelSelectorRequirement{{Key: "foo", Operator: "foo", Values: []string{"foo"}}}
			desired.Spec.Selector.MatchExpressions = []metav1.LabelSelectorRequirement{{Key: "bar", Operator: "bar", Values: []string{"bar"}}}
			Expect(servicemonitor.AreSame(logger, current, desired)).To(BeFalse())
		})
	})

	Context("when evaluating MatchLabels", func() {
		It("should recognize they are the same", func() {
			Expect(servicemonitor.AreSame(logger, current, desired)).To(BeTrue())
		})

		It("should recognize they are different content", func() {
			desired.Spec.Selector.MatchLabels["foo"] = "bar"
			Expect(servicemonitor.AreSame(logger, current, desired)).To(BeFalse())
		})
	})

	Context("when evaluating PodTargetLabels", func() {
		It("should recognize they are the same", func() {
			Expect(servicemonitor.AreSame(logger, current, desired)).To(BeTrue())
		})

		It("should recognize they are different content", func() {
			desired.Spec.PodTargetLabels = append(desired.Spec.PodTargetLabels, "foo")
			Expect(servicemonitor.AreSame(logger, current, desired)).To(BeFalse())
		})
	})

	Context("when evaluating Endpoints", func() {
		It("should recognize they are the same", func() {
			Expect(servicemonitor.AreSame(logger, current, desired)).To(BeTrue())
		})

		It("should recognize they are different content", func() {
			desired.Spec.Endpoints = append(desired.Spec.Endpoints, monitoringv1.Endpoint{})
			Expect(servicemonitor.AreSame(logger, current, desired)).To(BeFalse())
		})

		It("should recognize they are different content", func() {
			desired.Spec.Endpoints = append(desired.Spec.Endpoints, monitoringv1.Endpoint{
				Port:   "8080",
				Path:   "/test",
				Scheme: "http",
			})
			current.Spec.Endpoints = append(current.Spec.Endpoints, monitoringv1.Endpoint{})
			Expect(servicemonitor.AreSame(logger, current, desired)).To(BeFalse())
		})
	})
})
