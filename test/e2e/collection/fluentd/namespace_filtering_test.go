package fluentd

import (
	"fmt"
	"github.com/openshift/cluster-logging-operator/internal/constants"
	framework "github.com/openshift/cluster-logging-operator/test/framework/e2e"
	"path/filepath"
	"runtime"

	"github.com/ViaQ/logerr/log"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	logging "github.com/openshift/cluster-logging-operator/apis/logging/v1"
	"github.com/openshift/cluster-logging-operator/test/helpers"
	"github.com/openshift/cluster-logging-operator/test/helpers/oc"
	apps "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("[Collection] Namespace filtering", func() {
	_, filename, _, _ := runtime.Caller(0)
	log.Info("Running ", "filename", filename)
	var (
		err              error
		fluentDeployment *apps.Deployment
		e2e              = framework.NewE2ETestFramework()
		rootDir          string
	)
	appNamespace1 := "application-ns1"
	appNamespace2 := "application-ns2"

	BeforeEach(func() {
		if _, err = oc.Literal().From("oc create ns %s", appNamespace1).Run(); err != nil {
			Fail("failed to create namespace")
		}
		if _, err = oc.Literal().From("oc create ns %s", appNamespace2).Run(); err != nil {
			Fail("failed to create namespace")
		}
	})
	BeforeEach(func() {
		if err := e2e.DeployLogGeneratorWithNamespace(appNamespace1); err != nil {
			Fail(fmt.Sprintf("Timed out waiting for the log generator 1 to deploy: %v", err))
		}
		if err := e2e.DeployLogGeneratorWithNamespace(appNamespace2); err != nil {
			Fail(fmt.Sprintf("Timed out waiting for the log generator 2 to deploy: %v", err))
		}
		rootDir = filepath.Join(filepath.Dir(filename), "..", "..", "..", "..", "/")
		if fluentDeployment, err = e2e.DeployFluentdReceiver(rootDir, false); err != nil {
			Fail(fmt.Sprintf("Unable to deploy fluent receiver: %v", err))
		}

		forwarder := &logging.ClusterLogForwarder{
			TypeMeta: metav1.TypeMeta{
				Kind:       logging.ClusterLogForwarderKind,
				APIVersion: logging.GroupVersion.String(),
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "instance",
			},
			Spec: logging.ClusterLogForwarderSpec{
				Inputs: []logging.InputSpec{
					{
						Name: "application-logs",
						Application: &logging.Application{
							Namespaces: []string{appNamespace1},
						},
					},
				},
				Outputs: []logging.OutputSpec{
					{
						Name: fluentDeployment.ObjectMeta.Name,
						Type: logging.OutputTypeFluentdForward,
						URL:  fmt.Sprintf("tcp://%s.%s.svc:24224", fluentDeployment.ObjectMeta.Name, fluentDeployment.Namespace),
					},
				},
				Pipelines: []logging.PipelineSpec{
					{
						Name:       "test-app",
						OutputRefs: []string{fluentDeployment.ObjectMeta.Name},
						InputRefs:  []string{"application-logs"},
					},
				},
			},
		}
		if err := e2e.CreateClusterLogForwarder(forwarder); err != nil {
			Fail(fmt.Sprintf("Unable to create an instance of clusterlogforwarder: %v", err))
		}
		cr := helpers.NewClusterLogging(helpers.ComponentTypeCollector)
		if err := e2e.CreateClusterLogging(cr); err != nil {
			Fail(fmt.Sprintf("Unable to create an instance of cluster logging: %v", err))
		}
		if err := e2e.WaitFor(helpers.ComponentTypeCollector); err != nil {
			Fail(fmt.Sprintf("Failed waiting for component %s to be ready: %v", helpers.ComponentTypeCollector, err))
		}

	})
	It("should send logs from one namespace only", func() {
		Expect(e2e.LogStores[fluentDeployment.GetName()].HasApplicationLogs(framework.DefaultWaitForLogsTimeout)).To(BeTrue(), "Expected to find stored application logs")

		logs, err := e2e.LogStores[fluentDeployment.GetName()].ApplicationLogs(framework.DefaultWaitForLogsTimeout)
		Expect(err).To(BeNil(), fmt.Sprintf("Error fetching logs: %v", err))
		Expect(len(logs)).To(Not(Equal(0)), "There were no documents returned in the logs")

		// verify only appNamespace1 logs appear in Application logs
		for _, log := range logs {
			Expect(log.Kubernetes.NamespaceName).To(Equal(appNamespace1))
		}
	})

	AfterEach(func() {
		if _, err = oc.Literal().From("oc delete ns %s", appNamespace1).Run(); err != nil {
			Fail("failed to create namespace")
		}
		if _, err = oc.Literal().From("oc delete ns %s", appNamespace2).Run(); err != nil {
			Fail("failed to create namespace")
		}
		e2e.WaitForCleanupCompletion(appNamespace1, []string{"test"})
		e2e.WaitForCleanupCompletion(appNamespace2, []string{"test"})
		e2e.Cleanup()
		e2e.WaitForCleanupCompletion(constants.OpenshiftNS, []string{"fluent-receiver", "fluentd"})
		e2e.WaitForCleanupCompletion(constants.OpenshiftNS, []string{constants.CollectorName})
	}, framework.DefaultCleanUpTimeout)

})
