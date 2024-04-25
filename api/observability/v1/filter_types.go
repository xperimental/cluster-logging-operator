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

import "github.com/openshift/cluster-logging-operator/internal/utils/sets"

// Filter type constants, must match JSON tags of FilterTypeSpec fields.
const (
	FilterAddLabels       = "addLabels"
	FilterDetectMultiline = "detectMultiline"
	FilterDrop            = "drop"
	FilterKubeAPIAudit    = "kubeAPIAudit"
	FilterParse           = "parse"
	FilterPrune           = "prune"
)

var ReservedFilterTypeNames = sets.NewString(FilterAddLabels, FilterDetectMultiline, FilterKubeAPIAudit, FilterDrop, FilterParse, FilterPrune)

// FilterSpec defines a filter for log messages.
type FilterSpec struct {
	// Name used to refer to the filter from a `pipeline`.
	//
	// +kubebuilder:validation:minLength:=1
	// +required
	Name string `json:"name"`

	// Type of filter.
	//
	// +kubebuilder:validation:Enum:=addLabels;detectMultiline;drop;kubeAPIAudit;parse;prune
	// +required
	Type string `json:"type"`

	// +optional
	KubeAPIAudit KubeAPIAudit `json:"kubeAPIAudit,omitempty"`

	// A drop filter applies a sequence of tests to a log record and drops the record if any test passes.
	// Each test contains a sequence of conditions, all conditions must be true for the test to pass.
	// A DropTestsSpec contains an array of tests which contains an array of conditions
	// +optional
	DropTestsSpec []DropTest `json:"drop,omitempty"`

	// The PruneFilterSpec consists of two arrays, namely in and notIn, which dictate the fields to be pruned.
	// +optional
	PruneFilterSpec PruneFilterSpec `json:"prune,omitempty"`
}

type DropTest struct {
	// DropConditions is an array of DropCondition which are conditions that are ANDed together
	// +optional
	DropConditions []DropCondition `json:"test,omitempty"`
}

type DropCondition struct {
	// A dot delimited path to a field in the log record. It must start with a `.`.
	// The path can contain alpha-numeric characters and underscores (a-zA-Z0-9_).
	// If segments contain characters outside of this range, the segment must be quoted.
	// Examples: `.kubernetes.namespace_name`, `.log_type`, '.kubernetes.labels.foobar', `.kubernetes.labels."foo-bar/baz"`
	// +optional
	Field string `json:"field,omitempty"`

	// A regular expression that the field will match.
	// If the value of the field defined in the DropTest matches the regular expression, the log record will be dropped.
	// Must define only one of matches OR notMatches
	// +optional
	Matches string `json:"matches,omitempty"`

	// A regular expression that the field does not match.
	// If the value of the field defined in the DropTest does not match the regular expression, the log record will be dropped.
	// Must define only one of matches or notMatches
	// +optional
	NotMatches string `json:"notMatches,omitempty"`
}

type PruneFilterSpec struct {
	// `In` is an array of dot-delimited field paths. Fields included here are removed from the log record.
	// Each field path expression must start with a `.`.
	// The path can contain alpha-numeric characters and underscores (a-zA-Z0-9_).
	// If segments contain characters outside of this range, the segment must be quoted otherwise paths do NOT need to be quoted.
	// Examples: `.kubernetes.namespace_name`, `.log_type`, '.kubernetes.labels.foobar', `.kubernetes.labels."foo-bar/baz"`
	// NOTE1: `In` CANNOT contain `.log_type` or `.message` as those fields are required and cannot be pruned.
	// NOTE2: If this filter is used in a pipeline with GoogleCloudLogging, `.hostname` CANNOT be added to this list as it is a required field.
	// +optional
	In []string `json:"in,omitempty"`

	// `NotIn` is an array of dot-delimited field paths. All fields besides the ones listed here are removed from the log record
	// Each field path expression must start with a `.`.
	// The path can contain alpha-numeric characters and underscores (a-zA-Z0-9_).
	// If segments contain characters outside of this range, the segment must be quoted otherwise paths do NOT need to be quoted.
	// Examples: `.kubernetes.namespace_name`, `.log_type`, '.kubernetes.labels.foobar', `.kubernetes.labels."foo-bar/baz"`
	// NOTE1: `NotIn` MUST contain `.log_type` and `.message` as those fields are required and cannot be pruned.
	// NOTE2: If this filter is used in a pipeline with GoogleCloudLogging, `.hostname` MUST be added to this list as it is a required field.
	// +optional
	NotIn []string `json:"notIn,omitempty"`
}
