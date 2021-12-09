package aws

import (
	"os"
	"testing"
)

func TestSuiteKMS(tt *testing.T) {

	TestKeyArn := os.Getenv("KMS_KEY_ARN")

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
			{"Encrypt and Decrypt invalid ARN", "EncryptDecrypt", []string{"", ""}, "", false},
			{"Encrypt and Decrypt empty string", "EncryptDecrypt", []string{"", TestKeyArn}, "", true},
			{"Encrypt and Decrypt string", "EncryptDecrypt", []string{"This is a test!", TestKeyArn}, "This is a test!", true},
		}
	)

	for _, test := range tests {
		switch test.action {
		case "EncryptDecrypt":
			ciphered, err1 := KMSEncrypt(test.inputs[0], test.inputs[1])
			plaintext, err2 := KMSDecrypt(ciphered)
			norm = plaintext
			success = (err1 == nil && err2 == nil)
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
