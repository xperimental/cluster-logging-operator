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
	openshiftv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/cluster-logging-operator/internal/utils/sets"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"time"
)

// NOTE: The Enum validation on OutputSpec.Type must be updated if the list of
// known types changes.

// Output type constants, must match JSON tags of OutputTypeSpec fields.
const (
	OutputTypeAzureMonitor       = "azureMonitor"
	OutputTypeCloudwatch         = "cloudwatch"
	OutputTypeElasticsearch      = "elasticsearch"
	OutputTypeGoogleCloudLogging = "googleCloudLogging"
	OutputTypeHttp               = "http"
	OutputTypeKafka              = "kafka"
	OutputTypeLokiStack          = "lokiStack"
	OutputTypeSplunk             = "splunk"
	OutputTypeSyslog             = "syslog"
)

var (
	//OutputTypes is the set of supported output types
	OutputTypes = sets.NewString(
		OutputTypeAzureMonitor,
		OutputTypeCloudwatch,
		OutputTypeElasticsearch,
		OutputTypeGoogleCloudLogging,
		OutputTypeHttp,
		OutputTypeKafka,
		OutputTypeLokiStack,
		OutputTypeSplunk,
		OutputTypeSyslog,
	)
)

// OutputSpec defines a destination for log messages.
type OutputSpec struct {
	// Name used to refer to the output from a `pipeline`.
	//
	// +kubebuilder:validation:minLength:=1
	// +required
	Name string `json:"name,omitempty"`

	// Type of output sink.
	//
	// +kubebuilder:validation:Enum:=azureMonitor;cloudwatch;elasticsearch;http;kafka;lokiStack;googleCloudLogging;splunk;syslog
	// +required
	Type string `json:"type,omitempty"`

	OutputTypeSpec `json:",inline"`

	// TLS contains settings for controlling options on TLS client connections.
	//
	// +optional
	// +nullable
	TLS *OutputTLSSpec `json:"tls,omitempty"`

	// Limit imposes a limit in records-per-second on the total aggregate rate of logs forwarded
	// to this output from any given collector container. The total log flow from an individual collector
	// container to this output cannot exceed the limit.  Generally, one collector is deployed per cluster node
	// Logs may be dropped to enforce the limit. Missing or 0 means no rate limit.
	//
	// +optional
	// +nullable
	Limit *LimitSpec `json:"rateLimit,omitempty"`

	// Tuning parameters for the output.  Specifying these parameters will alter the characteristics
	// of log forwarder which may be different from its behavior without the tuning.
	//
	// +optional
	// +nullable
	Tuning *BaseOutputTuningSpec `json:"tuning,omitempty"`
}

type OutputResourceSpec struct {
	ResourceTypeSpec `json:",inline"`

	// The CertificateAuthority to use.  Assumed to be ca-bundle.crt if not defined
	//
	// +optional
	// +nullable
	CACert *PriorityKeySpec `json:"cacert,omitempty"`

	// The public certificate to use in PEM format. Assumed to be tls.crt if not defined
	//
	// +optional
	// +nullable
	Cert *KeySpec `json:"cert,omitempty"`

	// The private certificate  to use in PEM format. Assumed to be tls.key if not defined
	//
	// +optional
	// +nullable
	Key *KeySpec `json:"key,omitempty"`

	// The TLS passphrase.  Assumed to be passphrase if not defined
	//
	// +optional
	// +nullable
	Passphrase *KeySpec `json:"passphrase,omitempty"`
}

// OutputTLSSpec contains options for TLS connections that are agnostic to the output type.
type OutputTLSSpec struct {
	// Resource is the secret or configmap to search for
	//
	// +required
	Resource OutputResourceSpec `json:"resource,omitempty"`

	// If InsecureSkipVerify is true, then the TLS client will be configured to ignore errors with certificates.
	//
	// This option is *not* recommended for production configurations.
	//
	// +optional
	InsecureSkipVerify bool `json:"insecureSkipVerify,omitempty"`

	// TLSSecurityProfile is the security profile to apply to the output connection
	//
	// +optional
	TLSSecurityProfile *openshiftv1.TLSSecurityProfile `json:"securityProfile,omitempty"`
}

type URLSpec struct {
	// URL to send log records to.
	//
	// An absolute URL, with a scheme. Valid schemes depend on `type`.
	// Special schemes `tcp`, `tls`, `udp` and `udps` are used for types that
	// have no scheme of their own. For example, to send syslog records using secure UDP:
	//
	//     { type: syslog, url: udps://syslog.example.com:1234 }
	//
	// Basic TLS is enabled if the URL scheme requires it (for example 'https' or 'tls').
	// The 'username@password' part of `url` is ignored.
	// Any additional authentication material is in the `secret`.
	// See the `secret` field for more details.
	//
	// +kubebuilder:validation:Pattern:=`^$|[a-zA-z]+:\/\/.*`
	// +required
	URL string `json:"url,omitempty"`
}

// BaseOutputTuningSpec tuning parameters for an output
type BaseOutputTuningSpec struct {
	DeliverySpec `json:",inline"`

	// MaxWrite limits the maximum payload in terms of bytes of a single "send" to the output.
	//
	// +optional
	MaxWrite *resource.Quantity `json:"maxWrite,omitempty"`

	// MinRetryDuration is the minimum time to wait between attempts to retry after delivery a failure.
	//
	// +optional
	MinRetryDuration *time.Duration `json:"minRetryDuration,omitempty"`

	// MaxRetryDuration is the maximum time to wait between retry attempts after a delivery failure.
	//
	// +optional
	MaxRetryDuration *time.Duration `json:"maxRetryDuration,omitempty"`
}

type CompressionSpec struct {
	// Compression causes data to be compressed before sending over the network.
	// It is an error if the compression type is not supported by the  output.
	//
	// +optional
	// +kubebuilder:validation:Enum:=gzip;none;snappy;zlib;zstd;lz4
	Compression string `json:"compression,omitempty"`
}

type DeliverySpec struct {
	// Delivery mode for log forwarding.
	//
	//  - AtLeastOnce (default): if the forwarder crashes or is re-started, any logs that were read before
	//    the crash but not sent to their destination will be re-read and re-sent. Note it is possible
	//    that some logs are duplicated in the event of a crash - log records are delivered at-least-once.
	//  - AtMostOnce: The forwarder makes no effort to recover logs lost during a crash. This mode may give
	//    better throughput, but could result in more log loss.
	//
	// +optional
	// +kubebuilder:validation:Enum:=AtLeastOnce;AtMostOnce
	// +kubebuilder:default:=AtLeastOnce
	Delivery string `json:"delivery,omitempty"`
}

// OutputTypeSpec is a union of optional additional configuration specific to an
// output type. The fields of this struct define the set of known output types.
type OutputTypeSpec struct {

	// +optional
	// +nullable
	Syslog *Syslog `json:"syslog,omitempty"`

	// +optional
	// +nullable
	Elasticsearch *Elasticsearch `json:"elasticsearch,omitempty"`

	// +optional
	// +nullable
	Kafka *Kafka `json:"kafka,omitempty"`

	// +optional
	// +nullable
	Cloudwatch *Cloudwatch `json:"cloudwatch,omitempty"`

	// +optional
	// +nullable
	LokiStack *LokiStack `json:"lokiStack,omitempty"`

	// +optional
	// +nullable
	GoogleCloudLogging *GoogleCloudLogging `json:"googleCloudLogging,omitempty"`

	// +optional
	// +nullable
	Splunk *Splunk `json:"splunk,omitempty"`

	// +optional
	// +nullable
	Http *Http `json:"http,omitempty"`

	// +optional
	// +nullable
	AzureMonitor *AzureMonitor `json:"azureMonitor,omitempty"`
}

// AuthorizationSpec  is the spec for providing typical authorization credentials
type AuthorizationSpec struct {
	v1.LocalObjectReference `json:",inline"`

	// Token is the bearer token to use for authorization requests. Assumed to be 'token' if not defined
	//
	// +optional
	// +nullable
	Token *PriorityKeySpec `json:"token,omitempty"`

	// Username.  Assumed to be 'username' if not defined
	//
	// +optional
	// +nullable
	Username *KeySpec `json:"username,omitempty"`

	// Password.  Assumed to be 'password' if not defined
	// +optional
	// +nullable
	Password *KeySpec `json:"password,omitempty"`
}

type AzureMonitorAuthorizationSpec struct {
	v1.LocalObjectReference `json:",inline"`

	// SharedKey is the `shared_key`
	//
	// +optional
	// +nullable
	SharedKey *KeySpec `json:"sharedKey,omitempty"`
}

type AzureMonitor struct {
	// Authorization specs authorization for communicating with the receiver
	//
	// +required
	Authorization AzureMonitorAuthorizationSpec `json:"authorization,omitempty"`

	// CustomerId che unique identifier for the Log Analytics workspace.
	// https://learn.microsoft.com/en-us/azure/azure-monitor/logs/data-collector-api?tabs=powershell#request-uri-parameters
	CustomerId string `json:"customerId,omitempty"`

	// LogType the record type of the data that is being submitted.
	// Can only contain letters, numbers, and underscores (_), and may not exceed 100 characters.
	// https://learn.microsoft.com/en-us/azure/azure-monitor/logs/data-collector-api?tabs=powershell#request-headers
	LogType string `json:"logType,omitempty"`

	// AzureResourceId the Resource ID of the Azure resource the data should be associated with.
	// https://learn.microsoft.com/en-us/azure/azure-monitor/logs/data-collector-api?tabs=powershell#request-headers
	//
	// +optional
	AzureResourceId string `json:"azureResourceId,omitempty"`

	// Host alternative host for dedicated Azure regions. (for example for China region)
	// https://docs.azure.cn/en-us/articles/guidance/developerdifferences#check-endpoints-in-azure
	//
	// +optional
	Host string `json:"host,omitempty"`

	// Tuning specs tuning for the output
	//
	// +optional
	// +nullable
	Tuning *BaseOutputTuningSpec `json:"tuning,omitempty"`
}

type CloudwatchAuthorizationSpec struct {
	v1.LocalObjectReference `json:",inline"`

	// AWSAccessKeyID. Assumed to be `aws_secret_access_key` if not defined
	//
	// +optional
	// +nullable
	AWSAccessKeyID *KeySpec `json:"awsAccessKeyID,omitempty"`

	// AWSSecretAccessKey. Assumed to be `aws_access_key_id` if not defined
	//
	// +optional
	// +nullable
	AWSSecretAccessKey *KeySpec `json:"awsSecretAccessKey,omitempty"`

	// Credentials specifies the `credentials`  for STS enabled clusters.  Assumed to be 'credentials' if not defined
	//
	// +optional
	// +nullable
	Credentials *KeySpec `json:"credentials,omitempty"`

	// RoleArn specifies the `role_arn specifying a properly formatted role arn for STS enabled clusters
	// or for sts-enabled clusters `credentials` or `role_arn` key specifying a properly formatted role arn
	//
	// +optional
	// +nullable
	RoleArn *KeySpec `json:"roleARN,omitempty"`
}

type CloudwatchTuningSpec struct {
	BaseOutputTuningSpec `json:",inline"`

	// Compression causes data to be compressed before sending over the network.
	// It is an error if the compression type is not supported by the output.
	//
	// +optional
	// +kubebuilder:validation:Enum:=gzip;none;snappy;zlib;zstd;lz4
	// +kubebuilder:default:=none
	Compression string `json:"compression,omitempty"`
}

// Cloudwatch provides configuration for the output type `cloudwatch`
type Cloudwatch struct {
	// Authorization specs authorization for communicating with the receiver
	//
	// +required
	Authorization CloudwatchAuthorizationSpec `json:"authorization,omitempty"`

	// Tuning specs tuning for the output
	//
	// +optional
	// +nullable
	Tuning *CloudwatchTuningSpec `json:"tuning,omitempty"`

	// +required
	Region string `json:"region,omitempty"`

	// GroupBy defines the strategy for grouping logstreams
	//
	// +required
	// +kubebuilder:validation:Enum:=logType;namespaceName;namespaceUUID
	GroupBy LogGroupByType `json:"groupBy,omitempty"`

	// GroupPrefix Add this prefix to all group names.
	//
	// Useful to avoid group name clashes if an AWS account is used for multiple clusters and
	// used verbatim (e.g. "" means no prefix). The default prefix is cluster-name/log-type
	//
	// +optional
	GroupPrefix *string `json:"groupPrefix,omitempty"`
}

// LogGroupByType defines a fixed strategy type
type LogGroupByType string

const (
	// LogGroupByLogType is the strategy to group logs by source(e.g. app, infra)
	LogGroupByLogType LogGroupByType = "logType"

	// LogGroupByNamespaceName is the strategy to use for grouping logs by namespace. Infrastructure and
	// audit logs are always grouped by "logType"
	LogGroupByNamespaceName LogGroupByType = "namespaceName"

	// LogGroupByNamespaceUUID  is the strategy to use for grouping logs by namespace UUID. Infrastructure and
	// audit logs are always grouped by "logType"
	LogGroupByNamespaceUUID LogGroupByType = "namespaceUUID"
)

type IndexSpec struct {
	// Index is the tenant for the logs. This supports template syntax
	// to allow dynamic per-event values
	//
	// +optional
	// +nullable
	Index string `json:"index,omitempty"`
}

type ElasticsearchAuthorizationSpec struct {
	AuthorizationSpec `json:",inline"`
}

type ElasticsearchTuningSpec struct {
	BaseOutputTuningSpec `json:",inline"`

	// Compression causes data to be compressed before sending over the network.
	//
	// +optional
	// +kubebuilder:validation:Enum:=none;gzip;zlib;zstd
	// +kubebuilder:default:=none
	Compression string `json:"compression,omitempty"`
}

type Elasticsearch struct {
	// Authorization specs authorization for communicating with the receiver
	//
	// +required
	Authorization ElasticsearchAuthorizationSpec `json:"authorization,omitempty"`

	// Tuning specs tuning for the output
	//
	// +optional
	// +nullable
	Tuning *ElasticsearchTuningSpec `json:"tuning,omitempty"`

	// defaults to: log_type-write
	IndexSpec `json:",inline"`

	// Version specifies the version of Elasticsearch to be used.
	// Must be one of: 6-8, where 8 is the default
	//
	// +kubebuilder:validation:Minimum:=6
	// +optional
	Version int `json:"version,omitempty"`
}

type GoogleCloudLoggingAuthorizationSpec struct {
	v1.LocalObjectReference `json:",inline"`

	// Credentials path to `google-application-credentials.json`.
	// Assumed to be `google-application-credentials.json` if not defined.
	//
	// +optional
	// +nullable
	Credentials *KeySpec `json:"credentials,omitempty"`
}

// GoogleCloudLogging provides configuration for sending logs to Google Cloud Logging.
// Exactly one of billingAccountID, organizationID, folderID, or projectID must be set.
type GoogleCloudLogging struct {
	// Authorization specs authorization for communicating with the receiver
	//
	// +optional
	Authorization GoogleCloudLoggingAuthorizationSpec `json:"authorization,omitempty"`

	// +optional
	BillingAccountID string `json:"billingAccountId,omitempty"`

	// +optional
	OrganizationID string `json:"organizationId,omitempty"`

	// +optional
	FolderID string `json:"folderId,omitempty"`

	// +optional
	ProjectID string `json:"projectId,omitempty"`

	// LogID is the log ID to which to publish logs. This identifies log stream.
	LogID string `json:"logId,omitempty"`
}

type HttpTuningSpec struct {
	BaseOutputTuningSpec `json:",inline"`

	// Compression causes data to be compressed before sending over the network.
	//
	// +optional
	// +kubebuilder:validation:Enum:=none;gzip;snappy;zlib
	// +kubebuilder:default:=none
	Compression string `json:"compression,omitempty"`
}

// Http provided configuration for sending json encoded logs to a generic http endpoint.
type Http struct {
	// Authorization specs authorization for communicating with the receiver
	//
	// +required
	Authorization AuthorizationSpec `json:"authorization,omitempty"`

	// Tuning specs tuning for the output
	//
	// +optional
	// +nullable
	Tuning *HttpTuningSpec `json:"tuning,omitempty"`

	URLSpec `json:",inline"`

	// Headers specify optional headers to be sent with the request
	//
	// +optional
	Headers map[string]string `json:"headers,omitempty"`

	// Timeout specifies the Http request timeout in seconds. If not set, 10secs is used.
	//
	// +optional
	Timeout int `json:"timeout,omitempty"`

	// Method specifies the Http method to be used for sending logs. If not set, 'POST' is used.
	//
	// +kubebuilder:validation:Enum:=GET;HEAD;POST;PUT;DELETE;OPTIONS;TRACE;PATCH
	// +optional
	Method string `json:"method,omitempty"`
}

type KafkaTuningSpec struct {
	DeliverySpec `json:",inline"`

	// MaxWrite limits the maximum payload in terms of bytes of a single "send" to the output.
	//
	// +optional
	MaxWrite *resource.Quantity `json:"maxWrite,omitempty"`

	// Compression causes data to be compressed before sending over the network.
	//
	// +optional
	// +kubebuilder:validation:Enum:=none;snappy;zstd;lz4
	// +kubebuilder:default:=none
	Compression string `json:"compression,omitempty"`
}

// KafkaAuthorizationSpec
type KafkaAuthorizationSpec struct {
	v1.LocalObjectReference `json:",inline"`

	// SASLEnabled assumed key sasl.enable and disabled by default. Override as needed
	//
	// +optional
	SASLEnabled bool `json:"saslEnabled,omitempty"`

	// SASLUsername assumed key username. Override as needed
	//
	// +optional
	// +nullable
	SASLUsername *KeySpec `json:"saslUsername,omitempty"`

	// SASLPassword assumed key password. Override as needed
	//
	// +optional
	// +nullable
	SASLPassword *KeySpec `json:"saslPassword,omitempty"`

	// SASLMechanisms assumed key sasl.mechanisms. Override as needed
	//
	// +optional
	// +nullable
	SASLMechanisms *KeySpec `json:"saslMechanisms,omitempty"`
}

// Kafka provides optional extra properties for `type: kafka`
type Kafka struct {

	// Authorization specs authorization for communicating with the receiver
	//
	// +required
	Authorization KafkaAuthorizationSpec `json:"authorization,omitempty"`

	// Tuning specs tuning for the output
	//
	// +optional
	// +nullable
	Tuning *KafkaTuningSpec `json:"tuning,omitempty"`

	URLSpec `json:",inline"`

	// Topic specifies the target topic to send logs to.
	//
	// +optional
	Topic string `json:"topic,omitempty"`

	// Brokers specifies the list of broker endpoints of a Kafka cluster.
	// The list represents only the initial set used by the collector's Kafka client for the
	// first connection only. The collector's Kafka client fetches constantly an updated list
	// from Kafka. These updates are not reconciled back to the collector configuration.
	// If none provided the target URL from the OutputSpec is used as fallback.
	//
	// +optional
	Brokers []string `json:"brokers,omitempty"`
}

// LokiAuthorizationSpec  is the spec for providing typical authorization credentials
type LokiAuthorizationSpec struct {
	v1.LocalObjectReference `json:",inline"`

	// Token is the bearer token to use for authorization requests
	//
	// +optional
	Token *KeySpec `json:"token,omitempty"`
}

type LokiTuningSpec struct {
	BaseOutputTuningSpec `json:",inline"`

	// Compression causes data to be compressed before sending over the network.
	//
	// +optional
	// +kubebuilder:validation:Enum:=none;gzip;snappy
	// +kubebuilder:default:=none
	Compression string `json:"compression,omitempty"`
}

// LokiStack provides optional extra properties for `type: loki`
type LokiStack struct {
	// Authorization specs authorization for communicating with the receiver
	//
	// +required
	Authorization LokiAuthorizationSpec `json:"authorization,omitempty"`

	// Tuning specs tuning for the output
	//
	// +optional
	Tuning *LokiTuningSpec `json:"tuning,omitempty"`

	// LabelKeys is a list of log record keys that will be used as Loki labels with the corresponding log record value.
	//
	// If LabelKeys is not set, the default keys are `[log_type, kubernetes.namespace_name, kubernetes.pod_name, kubernetes_host]`
	//
	// Note: Loki label names must match the regular expression "[a-zA-Z_:][a-zA-Z0-9_:]*"
	// Log record keys may contain characters like "." and "/" that are not allowed in Loki labels.
	// Log record keys are translated to Loki labels by replacing any illegal characters with '_'.
	// For example the default log record keys translate to these Loki labels: `log_type`, `kubernetes_namespace_name`, `kubernetes_pod_name`, `kubernetes_host`
	//
	// Note: the set of labels should be small, Loki imposes limits on the size and number of labels allowed.
	// See https://grafana.com/docs/loki/latest/configuration/#limits_config for more.
	// Loki queries can also query based on any log record field (not just labels) using query filters.
	//
	// +optional
	LabelKeys []string `json:"labelKeys,omitempty"`
}

// SplunkAuthorizationSpec  is the spec for providing typical authorization credentials
type SplunkAuthorizationSpec struct {
	v1.LocalObjectReference `json:",inline"`

	// Token is the splunk HEC token
	//
	// +optional
	Token *KeySpec `json:"token,omitempty"`
}

type SplunkTuningSpec struct {
	BaseOutputTuningSpec `json:",inline"`
}

// Splunk Deliver log data to Splunk’s HTTP Event Collector
// Provides optional extra properties for `type: splunk_hec` ('splunk_hec_logs' after Vector 0.23
type Splunk struct {
	// Authorization specs authorization for communicating with the receiver
	//
	// +required
	Authorization SplunkAuthorizationSpec `json:"authorization,omitempty"`

	// Tuning specs tuning for the output
	//
	// +optional
	// +nullable
	Tuning *SplunkTuningSpec `json:"tuning,omitempty"`

	URLSpec `json:",inline"`

	// defaults to: Splunk receiver's defined index
	IndexSpec `json:",inline"`
}

// Syslog provides optional extra properties for output type `syslog`
type Syslog struct {
	URLSpec `json:",inline"`

	// Severity to set on outgoing syslog records.
	//
	// Severity values are defined in https://tools.ietf.org/html/rfc5424#section-6.2.1
	// The value can be a decimal integer or one of these case-insensitive keywords:
	//
	//     Emergency Alert Critical Error Warning Notice Informational Debug
	//
	// +optional
	Severity string `json:"severity,omitempty"`

	// Facility to set on outgoing syslog records.
	//
	// Facility values are defined in https://tools.ietf.org/html/rfc5424#section-6.2.1.
	// The value can be a decimal integer. Facility keywords are not standardized,
	// this API recognizes at least the following case-insensitive keywords
	// (defined by https://en.wikipedia.org/wiki/Syslog#Facility_Levels):
	//
	//     kernel user mail daemon auth syslog lpr news
	//     uucp cron authpriv ftp ntp security console solaris-cron
	//     local0 local1 local2 local3 local4 local5 local6 local7
	//
	// +optional
	Facility string `json:"facility,omitempty"`

	// TrimPrefix is a prefix to trim from the tag.
	//
	// +optional
	TrimPrefix string `json:"trimPrefix,omitempty"`

	// Tag specifies a record field to use as tag.
	//
	// +optional
	Tag string `json:"tag,omitempty"`

	// PayloadKey specifies record field to use as payload.
	//
	// +optional
	PayloadKey string `json:"payloadKey,omitempty"`

	// AddLogSource adds log's source information to the log message
	// If the logs are collected from a process; namespace_name, pod_name, container_name is added to the log
	// In addition, it picks the originating process name and id(known as the `pid`) from the record
	// and injects them into the header field."
	//
	// +optional
	AddLogSource bool `json:"addLogSource,omitempty"`

	// AppName is APP-NAME part of the syslog-msg header
	//
	// AppName needs to be specified if using rfc5424
	//
	// +optional
	AppName string `json:"appName,omitempty"`

	// ProcID is PROCID part of the syslog-msg header
	//
	// ProcID needs to be specified if using rfc5424
	//
	// +optional
	ProcID string `json:"procID,omitempty"`

	// MsgID is MSGID part of the syslog-msg header
	//
	// MsgID needs to be specified if using rfc5424
	//
	// +optional
	MsgID string `json:"msgID,omitempty"`
}
