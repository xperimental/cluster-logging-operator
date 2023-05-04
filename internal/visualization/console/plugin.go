package console

import (
	"context"
	log "github.com/ViaQ/logerr/v2/log/static"
	logging "github.com/openshift/cluster-logging-operator/apis/logging/v1"
	"github.com/openshift/cluster-logging-operator/internal/logstore/lokistack"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ReconcilePlugin reconciles the console plugin to expose log querying of storage
func ReconcilePlugin(k8sClient client.Client, spec logging.ClusterLoggingSpec, owner client.Object, clusterVersion string, consoleSpec *logging.OCPConsoleSpec) error {
	lokiService := lokistack.LokiStackGatewayService(spec.LogStore)
	r := NewReconciler(k8sClient, NewConfig(owner, lokiService, FeaturesForOCP(clusterVersion)), consoleSpec)

	if (spec.LogStore != nil && spec.LogStore.Type == logging.LogStoreTypeLokiStack) ||
		(spec.Visualization != nil && spec.Visualization.Type == logging.VisualizationTypeOCPConsole) {
		log.V(3).Info("Enabling logging console plugin", "created-by", r.CreatedBy(), "loki-service", lokiService)
		return r.Reconcile(context.TODO())
	} else {
		log.V(3).Info("Removing logging console plugin", "created-by", r.CreatedBy(), "loki-service", lokiService)
		return r.Delete(context.TODO())
	}
}
