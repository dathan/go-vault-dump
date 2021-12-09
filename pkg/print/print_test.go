package print

import (
	"testing"
)

func TestSuitePrint(tt *testing.T) {

	var (
		norm    string
		success bool
		tests   = []struct {
			description string
			action      string
			inputs      map[string]interface{}
			normOutput  string
			isSuccess   bool
		}{
			{"Generate empty JSON", "json", nil, "{}", true},
			{"Generate empty YAML", "yaml", nil, "{}\n", true},
			{"Generate JSON", "json", map[string]interface{}{"foo": "bar", "bat": "baz"}, `{"bat":"baz","foo":"bar"}`, true},
			{"Generate YAML", "yaml", map[string]interface{}{"foo": "bar", "bat": "baz"}, "bat: baz\nfoo: bar\n", true},
			{"Output JSON", "stdout.json", map[string]interface{}{"foo": "bar", "bat": "baz"}, "", true},
			{"Output YAML", "stdout.yaml", map[string]interface{}{"foo": "bar", "bat": "baz"}, "", true},
		}
	)

	for _, test := range tests {
		switch test.action {
		case "stdout.json":
			success = Stdout(test.inputs, "json")
			norm = ""
		case "stdout.yaml":
			success = Stdout(test.inputs, "yaml")
			norm = ""
		case "json":
			output, err := ToJSON(test.inputs)
			success = (err == nil)
			norm = output
		case "yaml":
			output, err := ToYaml(test.inputs)
			success = (err == nil)
			norm = output
		}
		if success == test.isSuccess && (!success || norm == test.normOutput) {
			tt.Logf("PASS %s", test.description)
		} else if success != test.isSuccess {
			tt.Errorf("FAIL %s: expected %t got %t", test.description, test.isSuccess, success)
		} else {
			tt.Errorf("FAIL %s: expected '%s' got '%s'", test.description, test.normOutput, norm)
		}
	}
}
