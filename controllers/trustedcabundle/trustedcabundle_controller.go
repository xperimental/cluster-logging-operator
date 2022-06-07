package trustedcabundle

import (
	"context"
	loggingv1 "github.com/openshift/cluster-logging-operator/apis/logging/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"time"

	"github.com/openshift/cluster-logging-operator/internal/k8shandler"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

var (
	reconcilePeriod = 30 * time.Second
	reconcileResult = reconcile.Result{RequeueAfter: reconcilePeriod}
)

var _ reconcile.Reconciler = &ReconcileTrustedCABundle{}

//ReconcileTrustedCABundle reconciles the trusted CA bundle config map.
type ReconcileTrustedCABundle struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client client.Client
	scheme *runtime.Scheme
}

// Reconcile reads that state of the trusted CA bundle configmap objects for the
// collector and the visualization resources.
// When the user configured and/or system certs are updated, the pods are triggered to restart.
func (r *ReconcileTrustedCABundle) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {

	if err := k8shandler.ReconcileForTrustedCABundle(request.Name, r.client); err != nil {
		// Failed to reconcile - requeuing.
		return reconcileResult, err
	}

	return reconcile.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *ReconcileTrustedCABundle) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&loggingv1.ClusterLogging{}).
		Complete(r)
}
