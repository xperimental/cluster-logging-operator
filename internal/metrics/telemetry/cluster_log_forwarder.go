package telemetry

import (
	logging "github.com/openshift/cluster-logging-operator/apis/logging/v1"
)

func UpdateInfoFromCLF(forwarder logging.ClusterLogForwarder) {
	outputMap := forwarder.Spec.OutputMap()

	activeInputNames := map[string]bool{}
	activeOutputTypes := map[string]bool{}
	for _, pipeline := range forwarder.Spec.Pipelines {
		for _, inputName := range pipeline.InputRefs {
			activeInputNames[inputName] = true
		}

		for _, outputName := range pipeline.OutputRefs {
			if outputName == defaultOutputName {
				Data.CLFInfo.HasDefaultOutput = true
			}

			output, found := outputMap[outputName]
			if found {
				activeOutputTypes[output.Type] = true
			}
		}
	}

	Data.CLFInfo.NumPipelines = uint(len(forwarder.Spec.Pipelines))

	inputs := makeZeroStrings(len(forwarderInputTypes))
	for i, v := range forwarderInputTypes {
		if activeInputNames[v] {
			inputs[i] = "1"
		}
	}
	Data.CLFInfo.Inputs = inputs

	outputs := makeZeroStrings(len(forwarderOutputTypes))
	for i, v := range forwarderOutputTypes {
		if activeOutputTypes[v] {
			outputs[i] = "1"
		}
	}
	Data.CLFInfo.Outputs = outputs
}
