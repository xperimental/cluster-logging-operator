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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ClusterLogForwarderSpec defines the desired state of ClusterLogForwarder
type ClusterLogForwarderSpec struct {
	// Specification of the Collector deployment to define
	// resource limits and workload placement
	//
	// +optional
	Collector *CollectorSpec `json:"collector,omitempty"`

	// Inputs are named filters for log messages to be forwarded.
	//
	// There are three built-in inputs named `application`, `infrastructure` and
	// `audit`. You don't need to define inputs here if those are sufficient for
	// your needs. See `inputRefs` for more.
	//
	// +optional
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Forwarder Inputs"
	Inputs []InputSpec `json:"inputs,omitempty"`

	// Outputs are named destinations for log messages.
	//
	// +optional
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Forwarder Outputs"
	Outputs []OutputSpec `json:"outputs,omitempty"`

	// Filters are applied to log records passing through a pipeline.
	// There are different types of filter that can select and modify log records in different ways.
	// See [FilterTypeSpec] for a list of filter types.
	//
	// +optional
	Filters []FilterSpec `json:"filters,omitempty"`

	// Pipelines forward the messages selected by a set of inputs to a set of outputs.
	//
	// +required
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Forwarder Pipelines"
	Pipelines []PipelineSpec `json:"pipelines,omitempty"`

	// ServiceAccount points to the ServiceAccount resource used for the collector pods.
	//
	// +required
	ServiceAccount corev1.LocalObjectReference `json:"serviceAccount,omitempty"`
}

// CollectorSpec is spec to define scheduling and resources for a collector
type CollectorSpec struct {
	// The resource requirements for the collector
	//
	// +nullable
	// +optional
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Collector Resource Requirements",xDescriptors={"urn:alm:descriptor:com.tectonic.ui:resourceRequirements"}
	Resources *corev1.ResourceRequirements `json:"resources,omitempty"`

	// Define which Nodes the Pods are scheduled on.
	//
	// +nullable
	// +optional
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Collector Node Selector",xDescriptors={"urn:alm:descriptor:com.tectonic.ui:selector:core:v1:ConfigMap"}
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// Define the tolerations the Pods will accept
	//
	// +nullable
	// +optional
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`
}

// PipelineSpec link a set of inputs to a set of outputs.
type PipelineSpec struct {
	// Name is optional, but must be unique in the `pipelines` list if provided.
	//
	// +required
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Name",xDescriptors={"urn:alm:descriptor:com.tectonic.ui:text"}
	Name string `json:"name,omitempty"`

	// InputRefs lists the names (`input.name`) of inputs to this pipeline.
	//
	// The following built-in input names are always available:
	//
	// `application` selects all logs from application pods.
	//
	// `infrastructure` selects logs from openshift and kubernetes pods and some node logs.
	//
	// `audit` selects node logs related to security audits.
	//
	// +required
	// +listType:=map
	// +listMapKey:=name
	InputRefs []string `json:"inputRefs,omitempty"`

	// OutputRefs lists the names (`output.name`) of outputs from this pipeline.
	//
	// +required
	// +listType:=map
	// +listMapKey:=name
	OutputRefs []string `json:"outputRefs,omitempty"`

	// Filters lists the names of filters to be applied to records going through this pipeline.
	//
	// Each filter is applied in order.
	// If a filter drops a records, subsequent filters are not applied.
	// +optional
	// +listType:=map
	// +listMapKey:=name
	FilterRefs []string `json:"filterRefs,omitempty"`
}

type LimitSpec struct {
	// MaxRecordsPerSecond is the maximum number of log records
	// allowed per input/output in a pipeline
	//
	// +required
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Max Records Per Second",xDescriptors={"urn:alm:descriptor:com.tectonic.ui:number"}
	MaxRecordsPerSecond int64 `json:"maxRecordsPerSecond,omitempty"`
}

// ResourceTypeSpec is the spec for defining a key/value resource type
type ResourceTypeSpec struct {
	// The secret containing configuration or TLS information
	//
	// +required
	Secret *corev1.LocalObjectReference `json:"secret,omitempty"`
}

// ConfigMapOrSecretKey encodes a reference to a single field in either a ConfigMap or Secret in the same namespace.
type ConfigMapOrSecretKey struct {
	// Name of the key used to get the value in either the referenced ConfigMap or Secret.
	//
	// +required
	// +kubebuilder:validation:minLength:=1
	// +kubebuilder:validation:Required
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Key Name",xDescriptors={"urn:alm:descriptor:com.tectonic.ui:text"}
	Key string `json:"key,omitempty"`

	// Use ConfigMap if the value should be sourced from a ConfigMap in the same namespace.
	ConfigMap *corev1.LocalObjectReference `json:"configMap,omitempty"`

	// Use Secret if the value should be sourced from a Secret in the same namespace.
	Secret *corev1.LocalObjectReference `json:"secret,omitempty"`
}

// SecretKey encodes a reference to a single key in a Secret in the same namespace.
type SecretKey struct {
	// Name of the key used to get the value in either the referenced ConfigMap or Secret.
	//
	// +required
	// +kubebuilder:validation:minLength:=1
	// +kubebuilder:validation:Required
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Key Name",xDescriptors={"urn:alm:descriptor:com.tectonic.ui:text"}
	Key string `json:"key,omitempty"`

	// Use Secret if the value should be sourced from a Secret in the same namespace.
	//
	// +required
	// +kubebuilder:validation:Required
	Secret *corev1.LocalObjectReference `json:"secret,omitempty"`
}

// BearerToken allows configuring the source of a bearer token used for authentication.
// The token can either be read from a secret or from a Kubernetes ServiceAccount.
type BearerToken struct {
	SecretKey `json:",inline"`

	// ServiceAccount contains the name of the Kubernetes ServiceAccount that should be used for getting
	// an authorization token.
	ServiceAccount corev1.LocalObjectReference `json:"serviceAccount,omitempty"`
}

// ClusterLogForwarderStatus defines the observed state of ClusterLogForwarder
type ClusterLogForwarderStatus struct {
	// Conditions of the log forwarder.
	//
	// +operator-sdk:csv:customresourcedefinitions:type=status,displayName="Forwarder Conditions",xDescriptors={"urn:alm:descriptor:io.kubernetes.conditions"}
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// Inputs maps input name to condition of the input.
	//
	// +operator-sdk:csv:customresourcedefinitions:type=status,displayName="Input Conditions",xDescriptors={"urn:alm:descriptor:io.kubernetes.conditions"}
	Inputs ConditionMap `json:"inputs,omitempty"`

	// Outputs maps output name to condition of the output.
	//
	// +operator-sdk:csv:customresourcedefinitions:type=status,displayName="Output Conditions",xDescriptors={"urn:alm:descriptor:io.kubernetes.conditions"}
	Outputs ConditionMap `json:"outputs,omitempty"`

	// Filters maps filter name to condition of the filter.
	//
	// +operator-sdk:csv:customresourcedefinitions:type=status,displayName="Filter Conditions",xDescriptors={"urn:alm:descriptor:io.kubernetes.conditions"}
	Filters ConditionMap `json:"filters,omitempty"`

	// Pipelines maps pipeline name to condition of the pipeline.
	//
	// +operator-sdk:csv:customresourcedefinitions:type=status,displayName="Pipeline Conditions",xDescriptors={"urn:alm:descriptor:io.kubernetes.conditions"}
	Pipelines ConditionMap `json:"pipelines,omitempty"`
}

// ClusterLogForwarder is an API to configure forwarding logs.
//
// You configure forwarding by specifying a list of `pipelines`,
// which forward from a set of named inputs to a set of named outputs.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:categories=observability,shortName=clf
type ClusterLogForwarder struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ClusterLogForwarderSpec   `json:"spec,omitempty"`
	Status ClusterLogForwarderStatus `json:"status,omitempty"`
}

// ClusterLogForwarderList contains a list of ClusterLogForwarder
//
// +kubebuilder:object:root=true
type ClusterLogForwarderList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ClusterLogForwarder `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ClusterLogForwarder{}, &ClusterLogForwarderList{})
}
