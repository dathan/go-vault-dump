package dump

// root command expects a Vault path provided with no flag
// we verify this path exists and that the current token has access to it
// the two scenarios present themselves in the same way, so it can exist but look
// like it does not if your token is not granted access to see it

import (
	"fmt"
	"os"
	"strings"
	"sync"

	vaultapi "github.com/hashicorp/vault/api"

	"github.com/dathan/go-vault-dump/pkg/vault"
	alsoyaml "github.com/ghodss/yaml"
	"gopkg.in/yaml.v2"
)

// Config
type Config struct {
	Debug        bool
	Client       *vaultapi.Client
	inputPath    string
	outputPath   string
	encodingType string
	outputType   string
}

func (c *Config) GetOutputEncoding() string {
	return c.encodingType
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

func printToStdOut(s *sync.Map, o string) bool {
	m := syncToMap(s)
	switch o {
	case "json":
		fmt.Println(toJSON(m))
	case "yaml":
		fmt.Println(toYaml(m))
	default:
		// DebugMsg(fmt.Sprintf("Unexpected input %s. writeToFile only understands json and yaml", o))
		return false
	}
	return true
}

func syncToMap(s *sync.Map) map[interface{}]interface{} {
	m := make(map[interface{}]interface{})
	s.Range(func(key, val interface{}) bool {
		m[key] = val
		return true
	})
	return m
}

func toJSON(i interface{}) string {
	y, err := yaml.Marshal(i)
	j, err := alsoyaml.YAMLToJSON(y)
	CheckErr(err, "error when marshalling interface into []byte")
	return string(j)
}

func toYaml(i interface{}) string {
	y, err := yaml.Marshal(i)
	CheckErr(err, "error when marshalling interface into []byte")
	return string(y)
}

func updatePathIfKVv2(c *vaultapi.Client, path string) string {
	mountPath, v2, err := vault.IsKVv2(path, c)
	CheckErr(err, "error determining KV engine version")
	if v2 {
		path = vault.AddPrefixToVKVPath(path, mountPath, "metadata")
		CheckErr(err, "")
	}
	return path
}

func writeFile(data, path string) bool {
	f, err := os.Create(path)
	if err != nil {
		fmt.Println(err)
		f.Close()
		return false
	}

	b, err := f.WriteString(data)
	if err != nil {
		fmt.Println(err)
		return false
	}
	fmt.Println(string(b) + " bytes written successfully\n")

	err = f.Close()
	CheckErr(err, "failed to close file!")

	fmt.Println("file written successfully to " + path)
	return true
}

func writeToFile(s *sync.Map, outputEncoding, inputPath, outputPath string) bool {
	m := syncToMap(s)

	fileName := fmt.Sprintf("%s/%s.%s", outputPath, inputPath, outputEncoding)

	switch outputEncoding {
	case "json":
		_ = writeFile(toJSON(m), fileName)
	case "yaml":
		_ = writeFile(toYaml(m), fileName)
	default:
		// DebugMsg(fmt.Sprintf("Unexpected input %s. writeToFile only understands json and yaml", outputEncoding))
		return false
	}
	return true
}

// CheckErr is a helper function that panics if the
// error is not passed and prints the msg string before
func CheckErr(e error, msg string) {
	if e != nil {
		if msg != "" {
			fmt.Println(msg)
		}
		panic(e)
	}
}

// DebugMsg is a helper function that prints the message
// if the debug flag is set
func (c *Config) DebugMsg(msg string) {
	if c.Debug {
		fmt.Println(msg)
	}
}

// FindVaultSecrets
func FindVaultSecrets(c *Config, path string, smPointer *sync.Map, wgPointer *sync.WaitGroup) {
	wgPointer.Add(1)
	c.DebugMsg(path)

	go func(wg *sync.WaitGroup, path string) {
		secret, err := c.Client.Logical().List(path)
		CheckErr(err, "error listing path")

		if secret == nil || secret.Data == nil {
			panic(fmt.Sprintf("No value found at %s", path))
		}

		if _, ok := vault.ExtractListData(secret); !ok {
			panic(fmt.Sprintf("No entries found at %s", path))
		}

		for _, p := range secret.Data {
			for _, k := range p.([]interface{}) {
				newPath := path + "/" + k.(string)
				if isDir(k.(string)) { // type assertion
					FindVaultSecrets(c, vault.EnsureNoTrailingSlash(newPath), smPointer, wg)
				} else {
					// reconciling v2 secret engine requirement for list operation
					keyPath := strings.Replace(newPath, "metadata", "data", 1)
					c.DebugMsg(fmt.Sprintf("processing a secret at %s", keyPath))

					sec, err := c.Client.Logical().Read(keyPath)
					CheckErr(err, "")

					if sec != nil {
						smPointer.Store(keyPath, sec.Data)
					}

				}
			}
		}
		wg.Done()
	}(wgPointer, path)
}

// GetPathForOutput
func GetPathForOutput(path string) string {
	if path == "" {
		path = "/tmp"
	}
	return vault.EnsureNoTrailingSlash(path)
}

// GetPathFromInput
func GetPathFromInput(c *vaultapi.Client, input string) string {
	if input == "" {
		panic("missing input path from command line")
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
func ProcessOutput(c *Config, s *sync.Map) {
	switch c.outputType {
	case "file":
		writeToFile(s, c.encodingType, c.inputPath, c.outputType)
	case "stdout":
		printToStdOut(s, c.GetOutputEncoding())
	default:
		panic(fmt.Sprintf("Unexpected output type %s. ", c.outputType))
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

// SetOutputPath
func (c *Config) SetOutput(outputPath, encoding, outputType string) {
	c.outputPath = GetPathForOutput(outputPath)

	et, ok := validateOutputEncoding(encoding)
	if !ok {
		panic(fmt.Sprintf("Unexpected encoding type %s. ", encoding))
	}
	c.encodingType = et

	ot, ok := ValidateOutputType(outputType)
	if !ok {
		c.DebugMsg(fmt.Sprintf("Unexpected output type %s. ", outputType))
	}
	c.outputType = ot
}
