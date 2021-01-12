package dump

// root command expects a Vault path provided with no flag
// we verify this path exists and that the current token has access to it
// the two scenarios present themselves in the same way, so it can exist but look
// like it does not if your token is not granted access to see it

import (
	"fmt"
	"log"
	"runtime"

	"github.com/dathan/go-vault-dump/pkg/file"
	"github.com/dathan/go-vault-dump/pkg/print"
	"github.com/dathan/go-vault-dump/pkg/vault"
	vaultapi "github.com/hashicorp/vault/api"
)

// Config
type Config struct {
	Debug     bool
	Client    *vaultapi.Client
	InputPath string
	Output    *output
}

func New(c *Config) (*Config, error) {
	return &Config{
		Debug:     c.Debug,
		Client:    c.Client,
		InputPath: c.InputPath,
		Output:    c.Output,
	}, nil
}

func (c *Config) Secrets() error {
	secretScraper, err := NewSecretScraper(c.Client)
	if err != nil {
		return err
	}

	secretScraper.Run(c.InputPath, runtime.NumCPU())

	if len(secretScraper.Data) == 0 {
		log.Println("No secrets found")
		return nil
	}

	if err := c.ProcessOutput(secretScraper.Data); err != nil {
		return err
	}

	return nil
}

// func validateOutputEncoding(encodingType string) (string, bool) {
// 	switch encodingType {
// 	case "yaml":
// 	case "json":
// 		return encodingType, true
// 	}
// 	return "", false
// }

func isDir(p string) bool {
	lastChar := p[len(p)-1:]
	if lastChar != "/" {
		return false
	}
	return true
}

// func updatePathIfKVv2(c *vaultapi.Client, path string) string {
// 	mountPath, v2, err := vault.IsKVv2(path, c)
// 	if err != nil {
// 		log.Panicln(err, "error determining KV engine version")
// 	}

// 	if v2 {
// 		path = vault.AddPrefixToVKVPath(path, mountPath, "metadata")
// 	}
// 	return path
// }

// func writeFile(data, path string) bool {
// 	dirpath := filepath.Dir(path)
// 	if err := os.MkdirAll(dirpath, 0755); err != nil {
// 		log.Println(err)
// 		return false
// 	}

// 	f, err := os.Create(path)
// 	if err != nil {
// 		log.Println(err)
// 		f.Close()
// 		return false
// 	}
// 	f.Chmod(0600) // only you can access this file

// 	b, err := f.WriteString(data)
// 	if err != nil {
// 		log.Println(err)
// 		return false
// 	}
// 	log.Println(fmt.Sprint(b) + " bytes written successfully\n")

// 	if err = f.Close(); err != nil {
// 		log.Printf("failed to close file, %s", err.Error())
// 		return false
// 	}

// 	log.Println("file written successfully to " + path)
// 	return true
// }

func (c *Config) writeToFile(data map[string]interface{}) error {
	var (
		output string
		err    error
	)

	switch c.Output.GetEncoding() {
	case "yaml":
		output, err = print.ToYaml(data)
		if err != nil {
			return err
		}
	default:
		output, err = print.ToJSON(data)
		if err != nil {
			return err
		}
	}

	filename := fmt.Sprintf("%s/%s.%s", c.Output.GetPath(), c.InputPath, c.Output.GetEncoding())
	if ok := file.WriteFile(filename, output); !ok {
		return fmt.Errorf("failed to write %v", filename)
	}

	return nil
}

// // DebugMsg is a helper function that prints the message
// // if the debug flag is set
// func (c *Config) DebugMsg(msg string) {
// 	if c.Debug {
// 		log.Println(msg)
// 	}
// }

// func getSecret(config *Config, m map[interface{}]interface{}, secretChan chan string, errorChan chan error) {
// 	keyPath := <-secretChan
// 	secret, err := config.Client.Logical().Read(keyPath)
// 	if err != nil {
// 		log.Printf("failed to get secrets from %s, %s\n", keyPath, err.Error())
// 		errorChan <- err
// 		return
// 	}

// 	if secret != nil {
// 		fmt.Println(keyPath)
// 		m[keyPath] = secret.Data
// 	}
// }

// GetPathForOutput
func GetPathForOutput(path string) string {
	if path == "" {
		path = "/tmp/vault-dump"
	}
	return vault.EnsureNoTrailingSlash(path)
}

// // GetPathFromInput
// func GetPathFromInput(c *vaultapi.Client, input string) string {
// 	if input == "" {
// 		log.Panic("missing input path from command line")
// 	}
// 	u := updatePathIfKVv2(c, vault.SanitizePath(input))

// 	return vault.EnsureNoTrailingSlash(u)
// }

// func ValidateOutputType(outputType string) (string, bool) {
// 	switch outputType {
// 	case "file", "stdout", "k8s":
// 		return outputType, true
// 	default:
// 		return "", false
// 	}
// }

// ProcessOutput takes action based on inputs to complete the
// desired output result
func (c *Config) ProcessOutput(m map[string]interface{}) error {
	switch c.Output.GetKind() {
	// case "k8s":
	// 	// 	if err := ToKube(c, m); err != nil {
	// 	// 		log.Fatalln(err.Error())
	// 	// 	}
	case "stdout":
		print.Stdout(m, c.Output.GetEncoding())
	default:
		if err := c.writeToFile(m); err != nil {
			return err
		}

	}

	log.Printf("Discovered %v secrets\n", len(m))
	return nil
}

// // GetInputPath
// func (c *Config) GetInput() string {
// 	return c.inputPath
// }

// // SetInputPath
// func (c *Config) SetInput(i string) {
// 	c.inputPath = GetPathFromInput(c.Client, i)
// }

// SetOutput validates inputs before setting the Config attr
// func (c *Config) SetOutput(outputPath, outputEncoding, outputType string) {
// 	c.outputPath = GetPathForOutput(outputPath)

// 	oe, ok := validateOutputEncoding(outputEncoding)
// 	if !ok {
// 		log.Panicf("Unexpected encoding type %s. \n", outputEncoding)
// 	}
// 	c.outputEncoding = oe

// 	ot, ok := ValidateOutputType(outputType)
// 	if !ok {
// 		log.Panicf("Unexpected output type %s. ", outputType)
// 	}
// 	c.outputType = ot
// }
