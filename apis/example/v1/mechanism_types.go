package v1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +k8s:openapi-gen=true
// +kubebuilder:webhook:path=/validate-good-example.com-v1-mechanism,mutating=false,failurePolicy=fail,sideEffects=None,groups=good.example.com,resources=mechanisms,verbs=create;update,versions=v1,name=vmechanisms.good.example.com,admissionReviewVersions=v1

// A Mechanism used as a minimal example.
//
// +operator-sdk:csv:customresourcedefinitions:displayName="Mechanism"
type Mechanism struct {
	metav1.TypeMeta `json:",inline"`

	// Standard object's metadata
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Specification of the desired behavior of Mechanism
	Spec MechanismSpec `json:"spec,omitempty"`

	// Status defines the observed state of Mechanism
	Status MechanismStatus `json:"status,omitempty"`
}

type MechanismSpec struct{}

type MechanismStatus struct{}
