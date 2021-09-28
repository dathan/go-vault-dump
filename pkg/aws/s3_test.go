package aws

import (
	"strings"
	"testing"
)

func TestSuiteS3(tt *testing.T) {
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
			{"List missing bucket", "List", []string{"s3://xyzzy", ""}, "", false},
			{"Put to misssing bucket", "Put", []string{"s3://xyzzy/test.txt", "testing"}, "", false},
			{"Get from missing bucket", "Get", []string{"s3://xyzzy/test.txt"}, "", false},
			{"Put to missing bucket", "Put", []string{"s3://xyzzy/test.txt", ""}, "", false},
			{"List empty bucket", "List", []string{"s3://test", ""}, "", true},
			{"Put to bucket", "Put", []string{"s3://test/test.txt", "testing"}, "", true},
			{"List bucket", "List", []string{"s3://test", ""}, "test.txt", true},
			{"List bucket with ext", "List", []string{"s3://test", ".txt"}, "test.txt", true},
			{"List bucket missing ext", "List", []string{"s3://test", ".xyzzy"}, "", true},
			{"Get from bucket", "Get", []string{"s3://test/test.txt"}, "testing", true},
		}
	)
	for _, test := range tests {
		switch test.action {
		case "List":
			out, err := S3List(test.inputs[0], test.inputs[1])
			keys := make([]string, len(out))
			for ii, item := range out {
				keys[ii] = item.Key
			}
			norm = strings.Join(keys, ",")
			success = (err == nil)
		case "Get":
			out, err := S3Get(test.inputs[0])
			norm = string(out)
			success = (err == nil)
		case "Put":
			err := S3Put(test.inputs[0], test.inputs[1])
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
