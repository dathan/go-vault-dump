package print

import (
	"fmt"

	alsoyaml "github.com/ghodss/yaml"
	"gopkg.in/yaml.v2"
)

func Stdout(data map[string]interface{}, encoding string) bool {
	var (
		output string
		err    error
	)

	switch encoding {
	case "yaml":
		output, err = ToYaml(data)
		if err != nil {
			return false
		}
	default:
		output, err = ToJSON(data)
		if err != nil {
			return false
		}
	}

	fmt.Println(output)
	return true
}

func ToJSON(i interface{}) (string, error) {
	y, err := yaml.Marshal(i)
	j, err := alsoyaml.YAMLToJSON(y)
	if err != nil {
		return "", fmt.Errorf("error when marshalling interface into []byte: %w", err)
	}

	return string(j), nil
}

func ToYaml(i interface{}) (string, error) {
	y, err := yaml.Marshal(i)
	if err != nil {
		return "", fmt.Errorf("error when marshalling interface into []byte: %w", err)
	}

	return string(y), nil
}
