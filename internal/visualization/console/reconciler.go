package console

import (
	"context"
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/yaml"

	consolev1alpha1 "github.com/openshift/api/console/v1alpha1"
	logging "github.com/openshift/cluster-logging-operator/api/logging/v1"
	"github.com/openshift/cluster-logging-operator/internal/constants"
	"github.com/openshift/cluster-logging-operator/internal/runtime"
	"github.com/openshift/cluster-logging-operator/internal/utils"
	appv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metaerrors "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

func init() {
	utilruntime.Must(consolev1alpha1.AddToScheme(scheme.Scheme))
}

// Reconciler reconciles the console plugin state with the desired configuration
type Reconciler struct {
	Config
	c client.Client

	configMapHash string
	consolePlugin consolev1alpha1.ConsolePlugin
	configMap     corev1.ConfigMap
	deployment    appv1.Deployment
	service       corev1.Service
	visSpec       *logging.VisualizationSpec
}

// NewReconciler creates a Reconciler using client for config.
func NewReconciler(c client.Client, cf Config, visSpec *logging.VisualizationSpec) *Reconciler {
	r := &Reconciler{Config: cf, c: c, visSpec: visSpec}
	_ = r.each(func(m mutable) error {
		if m.o == &r.consolePlugin {
			runtime.Initialize(m.o, "", r.Name) // Plugin is Cluster scope
		} else {
			runtime.Initialize(m.o, r.Namespace(), r.Name)
		}
		return nil
	})
	return r
}

func ConsoleCapabilityEnabled(c client.Client, plugin consolev1alpha1.ConsolePlugin) bool {
	current := &consolev1alpha1.ConsolePlugin{}
	key := types.NamespacedName{Namespace: plugin.Namespace, Name: plugin.Name}
	err := c.Get(context.TODO(), key, current)

	return err == nil || !metaerrors.IsNoMatchError(err)
}

// Reconcile creates or updates cluster objects to match config.
func (r *Reconciler) Reconcile(ctx context.Context) error {
	// Do not reconcile console
	return nil
}

// Delete the consoleplugin and related objects.
func (r *Reconciler) Delete(ctx context.Context) error {
	// Do not reconcile console
	return nil
}

// each calls f for each object. Stops on first error and returns it.
func (r *Reconciler) each(f func(m mutable) error) error {
	for _, m := range []mutable{
		{&r.consolePlugin, r.mutateConsolePlugin},
		{&r.configMap, r.mutateConfigMap},
		{&r.deployment, r.mutateDeployment},
		{&r.service, r.mutateService},
	} {
		if err := f(m); err != nil {
			return err
		}
	}
	return nil
}

// mutable is an object and a mutate function that sets the desired state on the object.
// Suitable to be passed to controllerutil.CreateOrUpdate
type mutable struct {
	o      client.Object
	mutate controllerutil.MutateFn
}

// mutateCommon sets common labels for all objects.
func (r *Reconciler) mutateCommon(o client.Object) {
	o.SetLabels(map[string]string{
		constants.LabelApp:          r.Name,
		constants.LabelK8sName:      r.Name,
		constants.LabelK8sCreatedBy: r.CreatedBy(),
	})
}

// mutateOwned calls mutateCommon and also sets owner for owned objects.
func (r *Reconciler) mutateOwned(o client.Object) error {
	r.mutateCommon(o)
	return controllerutil.SetControllerReference(r.Owner, o, r.c.Scheme())
}

func (r *Reconciler) mutateConsolePlugin() error {
	o := &r.consolePlugin
	o.Spec = consolev1alpha1.ConsolePluginSpec{
		DisplayName: "Logging Console Plugin",
		Service: consolev1alpha1.ConsolePluginService{
			Name:      r.Name,
			Namespace: r.Namespace(),
			BasePath:  "/",
			Port:      r.pluginBackendPort(),
		},
		Proxy: []consolev1alpha1.ConsolePluginProxy{
			{
				Type:      "Service",
				Alias:     "backend",
				Authorize: true,
				Service: consolev1alpha1.ConsolePluginProxyServiceConfig{
					Name:      r.LokiService,
					Namespace: r.Namespace(),
					Port:      r.LokiPort,
				},
			},
		},
	}
	if r.Korrel8rName != "" && r.Korrel8rNamespace != "" {
		o.Spec.Proxy = append(o.Spec.Proxy, consolev1alpha1.ConsolePluginProxy{
			Type:      "Service",
			Alias:     r.Korrel8rName,
			Authorize: false,
			Service: consolev1alpha1.ConsolePluginProxyServiceConfig{
				Name:      r.Korrel8rName,
				Namespace: r.Korrel8rNamespace,
				Port:      8443,
			},
		})
	}
	r.mutateCommon(o)
	return nil
}

func (r *Reconciler) mutateConfigMap() error {
	var config string
	if r.visSpec != nil && r.visSpec.OCPConsole != nil {
		configYaml, err := yaml.Marshal(r.visSpec.OCPConsole)
		if err != nil {
			return err
		}
		config = string(configYaml)
	}
	o := &r.configMap
	o.Data = map[string]string{
		"config.yaml": config,
	}
	hash, err := utils.CalculateMD5Hash(config)
	if err != nil {
		return err
	}
	r.configMapHash = hash
	return r.mutateOwned(o)
}

// selector map used by service and deployment.
func (r *Reconciler) selector() map[string]string {
	return map[string]string{constants.LabelK8sName: r.Name, constants.LabelK8sCreatedBy: r.CreatedBy()}
}

func (r *Reconciler) mutateService() error {
	o := &r.service
	o.ObjectMeta.Annotations = map[string]string{constants.AnnotationServingCertSecretName: r.Name}
	// Don't replace Spec entirely it may contain immutable values like ClusterIP if we are updating.
	o.Spec.Selector = r.selector()
	o.Spec.Ports = []corev1.ServicePort{{
		Name:       fmt.Sprintf("%v-tcp", r.pluginBackendPort()),
		Protocol:   "TCP",
		Port:       r.pluginBackendPort(),
		TargetPort: intstr.IntOrString{IntVal: r.pluginBackendPort()},
	}}
	return r.mutateOwned(o)
}

func (r *Reconciler) mutateDeployment() error {
	nodeSelector, tolerations := getPluginNodeSelectorTolerations(r.visSpec)
	o := &r.deployment
	o.Spec = appv1.DeploymentSpec{
		Replicas: utils.GetPtr[int32](1),
		Selector: &metav1.LabelSelector{MatchLabels: r.selector()},
		Template: corev1.PodTemplateSpec{
			ObjectMeta: metav1.ObjectMeta{Labels: r.selector()},
			Spec: corev1.PodSpec{
				NodeSelector: nodeSelector,
				Tolerations:  tolerations,
				Containers: []corev1.Container{
					{
						Name:  r.Name,
						Image: r.Image,
						Ports: []corev1.ContainerPort{
							{
								ContainerPort: 9443,
								Protocol:      "TCP",
							},
						},
						Env: []corev1.EnvVar{
							{Name: "PLUGIN_CONF_HASH", Value: r.configMapHash},
						},
						Args: []string{
							"-port", "9443",
							"-features", strings.Join(r.Config.Features, ","),
							"-cert", "/var/serving-cert/tls.crt",
							"-key", "/var/serving-cert/tls.key",
							"-plugin-config-path", "/etc/plugin/config/config.yaml",
						},
						VolumeMounts: []corev1.VolumeMount{
							{
								Name:      "serving-cert",
								ReadOnly:  true,
								MountPath: "/var/serving-cert",
							},
							{
								Name:      "plugin-config",
								ReadOnly:  true,
								MountPath: "/etc/plugin/config",
							},
						},
					},
				},
				Volumes: []corev1.Volume{
					{
						Name: "serving-cert",
						VolumeSource: corev1.VolumeSource{
							Secret: &corev1.SecretVolumeSource{
								SecretName:  r.Name,
								DefaultMode: r.defaultMode(),
							},
						},
					},
					{
						Name: "plugin-config",
						VolumeSource: corev1.VolumeSource{
							ConfigMap: &corev1.ConfigMapVolumeSource{
								LocalObjectReference: corev1.LocalObjectReference{
									Name: r.Name,
								},
								DefaultMode: r.defaultMode(),
								Optional:    utils.GetPtr(true),
							},
						},
					},
				},
				RestartPolicy: "Always",
				DNSPolicy:     "ClusterFirst",
			},
		},
		Strategy: appv1.DeploymentStrategy{
			Type: "RollingUpdate",
			RollingUpdate: &appv1.RollingUpdateDeployment{
				MaxUnavailable: &intstr.IntOrString{
					Type:   intstr.Type(1),
					StrVal: "25%",
				},
				MaxSurge: &intstr.IntOrString{
					Type:   intstr.Type(1),
					StrVal: "25%",
				},
			},
		},
	}
	return r.mutateOwned(o)
}

func getPluginNodeSelectorTolerations(visSpec *logging.VisualizationSpec) (map[string]string, []corev1.Toleration) {
	if visSpec == nil {
		return nil, nil
	}

	return visSpec.NodeSelector, visSpec.Tolerations
}
