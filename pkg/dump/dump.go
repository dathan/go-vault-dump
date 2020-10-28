package dump

// root command expects a Vault path provided with no flag
// we verify this path exists and that the current token has access to it
// the two scenarios present themselves in the same way, so it can exist but look
// like it does not if your token is not granted access to see it

import (
	"fmt"
	"log"
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
	f, err := os.Create(path)
	if err != nil {
		log.Println(err)
		f.Close()
		return false
	}

	b, err := f.WriteString(data)
	if err != nil {
		log.Println(err)
		return false
	}
	log.Println(string(b) + " bytes written successfully\n")

	if err = f.Close(); err != nil {
		log.Printf("failed to close file, %s", err.Error())
		return false
	}

	log.Println("file written successfully to " + path)
	return true
}

func writeToFile(s *sync.Map, outputEncoding, inputPath, outputPath string) bool {
	m := syncToMap(s)

	fileName := fmt.Sprintf("%s/%s.%s", outputPath, inputPath, outputEncoding)

	switch outputEncoding {
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
		// DebugMsg(fmt.Sprintf("Unexpected input %s. writeToFile only understands json and yaml", outputEncoding))
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

// FindVaultSecrets
func FindVaultSecrets(c *Config, path string, smPointer *sync.Map, wgPointer *sync.WaitGroup) error {
	wgPointer.Add(1)
	c.DebugMsg(path)

	errChan := make(chan error, 1)
	go walker(path, c, smPointer, wgPointer, errChan)

	wgPointer.Wait()
	close(errChan)
	return <-errChan
}

func walker(path string, c *Config, sm *sync.Map, wg *sync.WaitGroup, errChan chan error) {
	defer wg.Done()

	secret, err := c.Client.Logical().List(path)
	if err != nil {
		select {
		case errChan <- err:
			log.Println("error listing path, " + err.Error())
		default:
			log.Println("another error occurred, " + err.Error())
		}
	}

	if secret == nil || secret.Data == nil {
		select {
		case errChan <- err:
			log.Printf("No value found at %s\n", path)
		default:
			log.Println("another error occurred")
		}
	} else if _, ok := vault.ExtractListData(secret); !ok {
		select {
		case errChan <- err:
			log.Printf("No entries found at %s\n", path)
		default:
			log.Println("another error occurred")
		}
	} else {
		for _, p := range secret.Data {
			for _, k := range p.([]interface{}) {
				newPath := path + "/" + k.(string)
				if isDir(k.(string)) { // type assertion
					FindVaultSecrets(c, vault.EnsureNoTrailingSlash(newPath), sm, wg)
				} else {
					// reconciling v2 secret engine requirement for list operation
					keyPath := strings.Replace(newPath, "metadata", "data", 1)
					c.DebugMsg(fmt.Sprintf("processing a secret at %s", keyPath))

					sec, err := c.Client.Logical().Read(keyPath)
					if err != nil {
						log.Printf("failed to get secrets from %s, %s\n", keyPath, err.Error())
					}

					if sec != nil {
						sm.Store(keyPath, sec.Data)
					}

				}
			}
		}
	}
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

// SetOutputPath
func (c *Config) SetOutput(outputPath, encoding, outputType string) {
	c.outputPath = GetPathForOutput(outputPath)

	et, ok := validateOutputEncoding(encoding)
	if !ok {
		log.Panicf("Unexpected encoding type %s. \n", encoding)
	}
	c.encodingType = et

	ot, ok := ValidateOutputType(outputType)
	if !ok {
		c.DebugMsg(fmt.Sprintf("Unexpected output type %s. ", outputType))
	}
	c.outputType = ot
}
