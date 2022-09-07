package kafka

type insecureTLS struct {
	ComponentID string
}

func (i insecureTLS) Name() string {
	return "kafkaInsecureTLSTemplate"
}

func (i insecureTLS) Template() string {
	return `{{define "` + i.Name() + `" -}}
[sinks.{{.ComponentID}}.librdkafka_options]
"enable.ssl.certificate.verification" = "false"
{{- end}}`
}
