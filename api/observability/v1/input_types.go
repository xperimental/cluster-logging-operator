/*
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package v1

import (
	"github.com/openshift/cluster-logging-operator/internal/utils/sets"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Reserved input names.
const (
	InputNameApplication    = "application"    // Non-infrastructure container logs.
	InputNameInfrastructure = "infrastructure" // Infrastructure containers and system logs.
	InputNameAudit          = "audit"          // System audit logs.
	InputNameReceiver       = "receiver"       // Receiver to receive logs from non-cluster sources.
)

var ReservedInputNames = sets.NewString(InputNameApplication, InputNameInfrastructure, InputNameAudit, InputNameReceiver)

// InputSpec defines a selector of log messages for a given log type.
type InputSpec struct {
	// Name used to refer to the input of a `pipeline`.
	//
	// +kubebuilder:validation:minLength:=1
	// +required
	Name string `json:"name"`

	// Type of output sink.
	//
	// +kubebuilder:validation:Enum:=application;audit;infrastructure;receiver
	// +required
	Type string `json:"type,omitempty"`

	// NOTE: the following fields in this struct are deliberately _not_ `omitempty`.
	// An empty field means enable that input type with no filter.

	// Application, named set of `application` logs that
	// can specify a set of match criteria
	//
	// +optional
	// +nullable
	Application *Application `json:"application,omitempty"`

	// Infrastructure, Enables `infrastructure` logs.
	//
	// +optional
	// +nullable
	Infrastructure *Infrastructure `json:"infrastructure,omitempty"`

	// Audit, enables `audit` logs.
	//
	// +optional
	// +nullable
	Audit *Audit `json:"audit,omitempty"`

	// Receiver to receive logs from non-cluster sources.
	// +optional
	// +nullable
	Receiver *ReceiverSpec `json:"receiver,omitempty"`
}

// LabelSelector is a label query over a set of resources.
type LabelSelector metav1.LabelSelector

type ContainerInputTuningSpec struct {

	// RateLimitPerContainer is the limit applied to each container
	// by this input. This limit is applied per collector deployment.
	//
	// +optional
	// +nullable
	RateLimitPerContainer *LimitSpec `json:"rateLimitPerContainer,omitempty"`
}

// Application log selector.
// All conditions in the selector must be satisfied (logical AND) to select logs.
type Application struct {
	// Selector for logs from pods with matching labels.
	// Only messages from pods with these labels are collected.
	// If absent or empty, logs are collected regardless of labels.
	//
	// +optional
	// +nullable
	Selector *LabelSelector `json:"selector,omitempty"`

	// Tuning is the container input tuning spec for this container sources
	// +optional
	// +nullable
	Tuning *ContainerInputTuningSpec `json:"tuning,omitempty"`

	// Includes is the set of namespaces and containers to include when collecting logs.
	// Note: infrastructure namespaces are still excluded for "*" values unless a qualifying glob pattern is specified.
	//
	// +optional
	Includes []NamespaceContainerSpec `json:"includes,omitempty"`

	// Excludes is the set of namespaces and containers to ignore when collecting logs.
	// Takes precedence over Includes option.
	//
	// +optional
	Excludes []NamespaceContainerSpec `json:"excludes,omitempty"`
}

type NamespaceContainerSpec struct {

	// Namespace resources. Creates a combined file pattern together with Container resources.
	// Supports glob patterns and presumes "*" if ommitted.
	// Note: infrastructure namespaces are still excluded for "*" values unless a qualifying glob pattern is specified.
	//
	// +optional
	Namespace string `json:"namespace,omitempty"`

	// Container resources. Creates a combined file pattern together with Namespace resources.
	// Supports glob patterns and presumes "*" if ommitted.
	//
	// +optional
	Container string `json:"container,omitempty"`
}

// Infrastructure enables infrastructure logs.
// Sources of these logs:
// * container workloads deployed to namespaces: default, kube*, openshift*
// * journald logs from cluster nodes
type Infrastructure struct {

	// Sources defines the list of infrastructure sources to collect.
	// This field is optional and omission results in the collection of all infrastructure sources.
	//  Valid sources are: node, container
	//
	// +optional
	Sources []string `json:"sources,omitempty"`
}

const (

	// InfrastructureSourceNode are journald logs from the node
	InfrastructureSourceNode string = "node"

	// InfrastructureSourceContainer are container logs from workloads deployed
	// in any of the following namespaces: default, kube*, openshift*
	InfrastructureSourceContainer string = "container"
)

var InfrastructureSources = sets.NewString(InfrastructureSourceNode, InfrastructureSourceContainer)

// Audit enables audit logs. Filtering may be added in future.
type Audit struct {
	// Sources defines the list of audit sources to collect.
	// This field is optional and its exclusion results in the collection of all audit sources.
	// Valid sources are: kubeAPI, openshiftAPI, auditd, ovn
	//
	// +optional
	Sources []string `json:"sources,omitempty"`
}

const (

	// AuditSourceKube are audit logs from kubernetes API servers
	AuditSourceKube string = "kubeAPI"

	// AuditSourceOpenShift are audit logs from OpenShift API servers
	AuditSourceOpenShift string = "openshiftAPI"

	// AuditSourceAuditd are audit logs from a node auditd service
	AuditSourceAuditd string = "auditd"

	// AuditSourceOVN are audit logs from an Open Virtual Network service
	AuditSourceOVN string = "ovn"
)

var AuditSources = sets.NewString(AuditSourceKube, AuditSourceOpenShift, AuditSourceAuditd, AuditSourceOVN)

const (
	ReceiverTypeHttp   = "http"
	ReceiverTypeSyslog = "syslog"

	// InputReceiverFormatKubeAPIAudit Log events in k8s list format, e.g. API audit log events.
	InputReceiverFormatKubeAPIAudit = "kubeAPIAudit"
)

var ReservedInputReceiverNames = sets.NewString(ReceiverTypeHttp, ReceiverTypeSyslog)

// ReceiverSpec is a union of input Receiver types.
type ReceiverSpec struct {

	// Type of Receiver plugin.
	// +kubebuilder:validation:Enum:=http;syslog
	// +required
	Type string `json:"type,omitempty"`

	// TLS contains settings for controlling options of TLS connections.
	// +optional
	// +nullable
	TLS *InputTLSSpec `json:"tls,omitempty"`

	// Port the Receiver listens on. It must be a value between 1024 and 65535
	// +kubebuilder:default:=8443
	// +kubebuilder:validation:Minimum:=1024
	// +kubebuilder:validation:Maximum:=65535
	// +optional
	Port int32 `json:"port"`

	// +optional
	// +nullable
	HTTP *HTTPReceiver `json:"http,omitempty"`
}

// HTTPReceiver receives encoded logs as a HTTP endpoint.
type HTTPReceiver struct {

	// Format is the format of incoming log data.
	//
	// +kubebuilder:validation:Enum:=kubeAPIAudit
	// +required
	Format string `json:"format"`
}

// InputTLSSpec contains options for TLS connections that are agnostic to the input type.
type InputTLSSpec struct {
	ResourceTypeSpec `json:",inline"`

	// The CertificateAuthority to use. Assume ca-bundle.crt or override
	// +optional
	// +nullable
	CACert *PriorityKeySpec `json:"cacert,omitempty"`

	// The public certificate to use in PEM format. Assume tls.crt or override
	// +optional
	// +nullable
	Cert *KeySpec `json:"cert,omitempty"`

	// The private certificate  to use in PEM format. Assume tls.key or override
	// +optional
	// +nullable
	Key *KeySpec `json:"key,omitempty"`
}
