package vector

import (
	"github.com/go-logr/logr"
	logging "github.com/openshift/cluster-logging-operator/apis/logging/v1"
	"github.com/openshift/cluster-logging-operator/internal/generator"
	corev1 "k8s.io/api/core/v1"
)

//nolint:govet // using declarative style
func Conf(logger logr.Logger, clspec *logging.ClusterLoggingSpec, secrets map[string]*corev1.Secret, clfspec *logging.ClusterLogForwarderSpec, op generator.Options) []generator.Section {
	return []generator.Section{
		{
			Sources(clfspec, op),
			`
			Set of all input sources, as defined in CLF spec
			 - kubernetes_logs
			 - journald
			 - file
			 - internal_metrics
			`,
		},
		{
			NormalizeLogs(clfspec, op),
			`
			- set 'level' field 
			- rename fields as per data model
			- remove unused fields
			`,
		},
		{
			Inputs(clfspec, op),
			`
			- Route logs by log types (app, infra, audit)
			- Handle user defined inputs
			`,
		},
		{
			Pipelines(clfspec, op),
			`
			- Add pipeline labels
			`,
		},
		{
			Outputs(logger, clspec, secrets, clfspec, op),
			`Set of all output sinks, as defined by CLF spec
			- elasticsearch
			- loki
			- kafka
			`,
		},
	}
}
