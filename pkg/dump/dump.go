package dump

// root command expects a Vault path provided with no flag
// we verify this path exists and that the current token has access to it
// the two scenarios present themselves in the same way, so it can exist but look
// like it does not if your token is not granted access to see it

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	vaultapi "github.com/hashicorp/vault/api"

	"github.com/dathan/go-vault-dump/pkg/vault"
	alsoyaml "github.com/ghodss/yaml"
	"gopkg.in/yaml.v2"
)

// Config
type Config struct {
	Debug          bool
	Client         *vaultapi.Client
	inputPath      string
	outputPath     string
	outputEncoding string
	outputType     string
}

func validateOutputEncoding(encodingType string) (string, bool) {
	switch encodingType {
	case "yaml":
		return "yaml", true
	case "json":
		return "json", true
	default:
		return "", false
	}
}

func isDir(p string) bool {
	lastChar := p[len(p)-1:]
	if lastChar != "/" {
		return false
	}
	return true
}

func (c *Config) printToStdOut(m map[string]interface{}) bool {
	switch c.outputEncoding {
	case "json":
		j, e := toJSON(m)
		if e != nil {
			return false
		}
		fmt.Println(j)
	case "yaml":
		y, e := toYaml(m)
		if e != nil {
			return false
		}
		fmt.Println(toYaml(y))
	default:
		log.Printf("Unexpected input %s. writeToFile only understands json and yaml", c.outputEncoding)
		return false
	}
	return true
}

func toJSON(i interface{}) (string, error) {
	y, err := yaml.Marshal(i)
	j, err := alsoyaml.YAMLToJSON(y)
	if err != nil {
		return "", fmt.Errorf("error when marshalling interface into []byte: %w", err)
	}

	return string(j), nil
}

func toYaml(i interface{}) (string, error) {
	y, err := yaml.Marshal(i)
	if err != nil {
		return "", fmt.Errorf("error when marshalling interface into []byte: %w", err)
	}

	return string(y), nil
}

func updatePathIfKVv2(c *vaultapi.Client, path string) string {
	mountPath, v2, err := vault.IsKVv2(path, c)
	if err != nil {
		log.Panicln(err, "error determining KV engine version")
	}

	if v2 {
		path = vault.AddPrefixToVKVPath(path, mountPath, "metadata")
	}
	return path
}

func writeFile(data, path string) bool {
	dirpath := filepath.Dir(path)
	if err := os.MkdirAll(dirpath, 0755); err != nil {
		log.Println(err)
		return false
	}

	f, err := os.Create(path)
	if err != nil {
		log.Println(err)
		f.Close()
		return false
	}
	f.Chmod(0600) // only you can access this file

	b, err := f.WriteString(data)
	if err != nil {
		log.Println(err)
		return false
	}
	log.Println(fmt.Sprint(b) + " bytes written successfully\n")

	if err = f.Close(); err != nil {
		log.Printf("failed to close file, %s", err.Error())
		return false
	}

	log.Println("file written successfully to " + path)
	return true
}

func (c *Config) writeToFile(m map[string]interface{}) bool {
	inputPath := vault.SanitizePath(strings.Replace(c.inputPath, "/metadata", "", 1))
	fileName := fmt.Sprintf("%s/%s.%s", c.outputPath, inputPath, c.outputEncoding)

	var err error
	switch c.outputEncoding {
	case "json":
		j, e := toJSON(m)
		if e != nil {
			return false
		}
		_ = writeFile(j, fileName)
	case "yaml":
		y, e := toYaml(m)
		if e != nil {
			return false
		}
		_ = writeFile(y, fileName)
	default:
		log.Printf("Unexpected input %s. writeToFile only understands json and yaml", c.outputEncoding)
		return false
	}
	if err != nil {
		log.Println(err)
		return false
	}
	return true
}

// DebugMsg is a helper function that prints the message
// if the debug flag is set
func (c *Config) DebugMsg(msg string) {
	if c.Debug {
		log.Println(msg)
	}
}

func getSecret(config *Config, m map[interface{}]interface{}, secretChan chan string, errorChan chan error) {
	keyPath := <-secretChan
	secret, err := config.Client.Logical().Read(keyPath)
	if err != nil {
		log.Printf("failed to get secrets from %s, %s\n", keyPath, err.Error())
		errorChan <- err
		return
	}

	if secret != nil {
		fmt.Println(keyPath)
		m[keyPath] = secret.Data
	}
}

// GetPathForOutput
func GetPathForOutput(path string) string {
	if path == "" {
		path = "/tmp/vault-dump"
	}
	return vault.EnsureNoTrailingSlash(path)
}

// GetPathFromInput
func GetPathFromInput(c *vaultapi.Client, input string) string {
	if input == "" {
		log.Panic("missing input path from command line")
	}
	u := updatePathIfKVv2(c, vault.SanitizePath(input))

	return vault.EnsureNoTrailingSlash(u)
}

func ValidateOutputType(outputType string) (string, bool) {
	switch outputType {
	case "file", "stdout", "k8s":
		return outputType, true
	default:
		return "", false
	}
}

// ProcessOutput takes action based on inputs to complete the
// desired output result
func (c *Config) ProcessOutput(m map[string]interface{}) {
	switch c.outputType {
	case "file":
		c.writeToFile(m)
	case "stdout":
		c.printToStdOut(m)
	default:
		log.Panicf("Unexpected output type %s\n", c.outputType)
	}
}

// GetInputPath
func (c *Config) GetInput() string {
	return c.inputPath
}

// GetOutputPath
func (c *Config) GetOutput() string {
	return c.outputPath
}

// SetInputPath
func (c *Config) SetInput(i string) {
	c.inputPath = GetPathFromInput(c.Client, i)
}

// SetOutput validates inputs before setting the Config attr
func (c *Config) SetOutput(outputPath, outputEncoding, outputType string) {
	c.outputPath = GetPathForOutput(outputPath)

	oe, ok := validateOutputEncoding(outputEncoding)
	if !ok {
		log.Panicf("Unexpected encoding type %s. \n", outputEncoding)
	}
	c.outputEncoding = oe

	ot, ok := ValidateOutputType(outputType)
	if !ok {
		log.Panicf("Unexpected output type %s. ", outputType)
	}
	c.outputType = ot
}
