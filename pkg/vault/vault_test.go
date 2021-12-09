package vault

import (
	"os"
	"strings"
	"testing"
)

func TestSuite(tt *testing.T) {
	var (
		norm    string
		success bool
		tests   = []struct {
			description string
			action      string
			inputs      []string
			normOutput  string
			isSuccess   bool
		}{
			{"ListSecrets.0", "ListSecrets", []string{"/secret/"}, "foo/", true},
			{"ListSecrets.1", "ListSecrets", []string{"/secret/foo/"}, "bar", true},
			{"ListPolicies.0", "ListPolicies", nil, "default,root", true},
			{"PurgePaths.0", "PurgePaths", []string{"/secret/foo/"}, "", true},
		}
	)
	vc, _ := NewClient(&Config{
		Address: os.Getenv("VAULT_ADDR"),
		Token:   os.Getenv("VAULT_TOKEN"),
	})
	for _, test := range tests {
		switch test.action {
		case "ListSecrets":
			out, err := vc.ListSecrets(test.inputs[0])
			norm = strings.Join(out, ",")
			success = (err == nil)
		case "ListPolicies":
			out, err := vc.ListPolicies()
			norm = strings.Join(out, ",")
			success = (err == nil)
		case "PurgePaths":
			err := vc.PurgePaths(test.inputs)
			norm = ""
			success = (err == nil)
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
