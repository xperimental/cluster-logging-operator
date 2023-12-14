package telemetry

import (
	v1 "github.com/openshift/cluster-logging-operator/apis/logging/v1"
	"github.com/openshift/cluster-logging-operator/version"
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
	"strconv"
)

const (
	labelManagedStatus = "managedStatus"
	labelHealthStatus  = "healthStatus"
	labelVersion       = "version"
	labelPipelineInfo  = "pipelineInfo"
	labelDeployed      = "deployed"

	metricsPrefix     = "log_"
	defaultOutputName = "default"
)

var (
	forwarderInputTypes = []string{
		v1.InputNameAudit,
		v1.InputNameApplication,
		v1.InputNameInfrastructure,
	}
	forwarderOutputTypes = []string{
		v1.OutputTypeElasticsearch,
		v1.OutputTypeFluentdForward,
		v1.OutputTypeSyslog,
		v1.OutputTypeKafka,
		v1.OutputTypeLoki,
		v1.OutputTypeCloudwatch,
		v1.OutputTypeHttp,
		v1.OutputTypeGoogleCloudLogging,
		v1.OutputTypeSplunk,
	}
)

type clusterLoggingData struct {
	Version string
	Managed bool
	Healthy bool
}

type clusterLogForwarderData struct {
	Healthy          bool
	HasDefaultOutput bool
	NumPipelines     uint
	// Inputs contains the label values for the different inputs listed in "forwarderInputTypes".
	// The value can either be "0" or "1" depending on whether the listed input is present in the configuration.
	// The order of the values needs to match the keys present in "forwarderInputTypes".
	Inputs []string
	// Outputs contains the label values for the different inputs listed in "forwarderOutputTypes".
	// The value can either be "0" or "1" depending on whether the listed input is present in the configuration.
	// The order of the values needs to match the keys present in "forwarderOutputTypes".
	Outputs []string
}

type logFileMetricExporterData struct {
	Deployed bool
	Healthy  bool
}

type telemetryData struct {
	CLInfo              clusterLoggingData
	CollectorErrorCount float64
	CLFInfo             clusterLogForwarderData
	LFMEInfo            logFileMetricExporterData
}

func newTelemetryData() *telemetryData {
	return &telemetryData{
		CLInfo: clusterLoggingData{
			Version: version.Version,
			Managed: false,
			Healthy: false,
		},
		CollectorErrorCount: 0,
		CLFInfo: clusterLogForwarderData{
			Healthy:      false,
			NumPipelines: 0,
			Inputs:       makeZeroStrings(len(forwarderInputTypes)),
			Outputs:      makeZeroStrings(len(forwarderOutputTypes)),
		},
		LFMEInfo: logFileMetricExporterData{
			Deployed: false,
			Healthy:  false,
		},
	}
}

var _ prometheus.Collector = &telemetryData{}

func (t *telemetryData) Describe(descs chan<- *prometheus.Desc) {
	descs <- clusterLoggingInfoDesc
	descs <- collectorErrorCountDesc
	descs <- clusterLogForwarderDesc
	descs <- forwarderInputInfoDesc
	descs <- forwarderOutputInfoDesc
	descs <- logFileMetricExporterInfoDesc
}

func (t *telemetryData) Collect(m chan<- prometheus.Metric) {
	m <- prometheus.MustNewConstMetric(clusterLoggingInfoDesc, prometheus.GaugeValue, 1.0, t.CLInfo.Version, boolLabel(t.CLInfo.Managed), boolLabel(t.CLInfo.Healthy))
	m <- prometheus.MustNewConstMetric(collectorErrorCountDesc, prometheus.CounterValue, t.CollectorErrorCount, t.CLInfo.Version)
	m <- prometheus.MustNewConstMetric(clusterLogForwarderDesc, prometheus.GaugeValue, 1.0, boolLabel(t.CLFInfo.Healthy), uintLabel(t.CLFInfo.NumPipelines))
	m <- prometheus.MustNewConstMetric(forwarderInputInfoDesc, prometheus.GaugeValue, 1.0, t.CLFInfo.Inputs...)

	outputLabels := append([]string{boolLabel(t.CLFInfo.HasDefaultOutput)}, t.CLFInfo.Outputs...)
	m <- prometheus.MustNewConstMetric(forwarderOutputInfoDesc, prometheus.GaugeValue, 1.0, outputLabels...)

	m <- prometheus.MustNewConstMetric(logFileMetricExporterInfoDesc, prometheus.GaugeValue, 1.0, boolLabel(t.LFMEInfo.Deployed), boolLabel(t.LFMEInfo.Healthy))
}

var (
	Data = newTelemetryData()

	clusterLoggingInfoDesc = prometheus.NewDesc(
		metricsPrefix+"logging_info",
		"Info metric containing general information about installed operator. Value is always 1.",
		[]string{labelVersion, labelManagedStatus, labelHealthStatus}, nil,
	)
	collectorErrorCountDesc = prometheus.NewDesc(
		metricsPrefix+"collector_error_count_total",
		"Counts the number of errors encountered by the operator reconciling the collector configuration",
		[]string{labelVersion}, nil,
	)
	clusterLogForwarderDesc = prometheus.NewDesc(
		metricsPrefix+"forwarder_pipeline_info",
		"Info metric containing information about deployed forwarders. Value is always 1.",
		[]string{labelHealthStatus, labelPipelineInfo}, nil,
	)

	forwarderInputInfoDesc = prometheus.NewDesc(
		"log_forwarder_input_info",
		"Info metric containing information about usage of pre-defined input names. Value is always 1.",
		forwarderInputTypes, nil,
	)

	forwarderOutputInfoDesc = prometheus.NewDesc(
		"log_forwarder_output_info",
		"Info metric containing information about usage of available output types. Value is always 1.",
		append([]string{defaultOutputName}, forwarderOutputTypes...), nil,
	)

	logFileMetricExporterInfoDesc = prometheus.NewDesc(
		"log_file_metric_exporter_info",
		"Info metric containing information about usage the file metric exporter. Value is always 1.",
		[]string{labelDeployed, labelHealthStatus}, nil,
	)
)

func RegisterMetrics() error {
	if err := metrics.Registry.Register(Data); err != nil {
		return err
	}

	return nil
}

func boolLabel(value bool) string {
	if value {
		return "1"
	}

	return "0"
}

func uintLabel(value uint) string {
	return strconv.FormatUint(uint64(value), 10)
}

func makeZeroStrings(length int) []string {
	result := make([]string, length)
	for i := range result {
		result[i] = "0"
	}

	return result
}
