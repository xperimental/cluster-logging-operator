package security

import (
	"path/filepath"

	loggingv1 "github.com/openshift/cluster-logging-operator/apis/logging/v1"
	"github.com/openshift/cluster-logging-operator/internal/constants"
	corev1 "k8s.io/api/core/v1"
)

type UserNamePass struct {
	Username string
	Password string
}

type SharedKey struct {
	Key string
}

type BearerToken struct {
	Token string
}

type TLSConf struct {
	ComponentID         string
	InsecureSkipVerify  bool
	CAPath              string
	ClientCertPath      string
	ClientKeyPath       string
	ClientKeyPassphrase string
}

func (t TLSConf) Name() string {
	return "vectorTLS"
}

func (t TLSConf) Template() string {
	return `
{{define "vectorTLS" -}}
[sinks.{{.ComponentID}}.tls]
enabled = true
{{- if .InsecureSkipVerify }}
verify_certificate = false
verify_hostname = false
{{- end }}
{{- with .CAPath }}
ca_file = "{{.}}"
{{- end }}
{{- if and .ClientCertPath .ClientKeyPath }}
crt_file = "{{.ClientCertPath}}"
key_file = "{{.ClientKeyPath}}"
{{- if .ClientKeyPassphrase }}
key_pass = "{{.ClientKeyPassphrase }}"
{{- end }}
{{- end }}
{{- end}}`
}

func NewTLSConf(componentID string, tlsSpec *loggingv1.OutputTLSSpec, secretName string, secret *corev1.Secret) (tlsConf TLSConf, hasKeys bool) {
	tlsConf = TLSConf{
		ComponentID:        componentID,
		InsecureSkipVerify: tlsSpec != nil && tlsSpec.InsecureSkipVerify,
	}
	if HasTLSCertAndKey(secret) {
		hasKeys = true
		tlsConf.ClientCertPath = SecretPath(secretName, constants.ClientCertKey)
		tlsConf.ClientKeyPath = SecretPath(secretName, constants.ClientPrivateKey)
	}
	if HasCABundle(secret) {
		hasKeys = true
		tlsConf.CAPath = SecretPath(secretName, constants.TrustedCABundleKey)
	}
	return tlsConf, hasKeys
}

var NoSecrets = map[string]*corev1.Secret{}

func HasUsernamePassword(secret *corev1.Secret) bool {
	return HasKeys(secret, constants.ClientUsername, constants.ClientPassword)
}

func HasTLSCertAndKey(secret *corev1.Secret) bool {
	return HasKeys(secret, constants.ClientCertKey, constants.ClientPrivateKey)
}

func HasCABundle(secret *corev1.Secret) bool {
	return HasKeys(secret, constants.TrustedCABundleKey)
}

func HasSharedKey(secret *corev1.Secret) bool {
	return HasKeys(secret, constants.SharedKey)
}

func HasPassphrase(secret *corev1.Secret) bool {
	return HasKeys(secret, constants.Passphrase)
}

func HasBearerTokenFileKey(secret *corev1.Secret) bool {
	return HasKeys(secret, constants.BearerTokenFileKey)
}

// GetKey if found return value and ok=true, else ok=false
func GetKey(secret *corev1.Secret, key string) (data []byte, ok bool) {
	if secret == nil {
		return nil, false
	}
	data, ok = secret.Data[key]
	return data, ok
}

// HasKeys true if all keys are present.
func HasKeys(secret *corev1.Secret, keys ...string) bool {
	for _, k := range keys {
		_, ok := GetKey(secret, k)
		if !ok {
			return false
		}
	}
	return true
}

func SecretPath(name string, file string) string {
	return filepath.Join("/var/run/ocp-collector/secrets", name, file)
}

// TryKeys try keys in turn return data for fist one present with ok=true.
// If none present return ok=false.
func TryKeys(secret *corev1.Secret, keys ...string) (data []byte, ok bool) {
	for _, k := range keys {
		data, ok := GetKey(secret, k)
		if ok {
			return data, true
		}
	}
	return nil, false
}

func GetFromSecret(secret *corev1.Secret, name string) string {
	if secret != nil {
		return string(secret.Data[name])
	}
	return ""
}
