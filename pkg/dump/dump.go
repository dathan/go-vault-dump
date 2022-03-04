package dump

// root command expects a Vault path provided with no flag
// we verify this path exists and that the current token has access to it
// the two scenarios present themselves in the same way, so it can exist but look
// like it does not if your token is not granted access to see it

import (
	"fmt"
	"log"
	"runtime"
	"sync"

	"github.com/dathan/go-vault-dump/pkg/file"
	"github.com/dathan/go-vault-dump/pkg/print"
	"github.com/dathan/go-vault-dump/pkg/vault"
)

// Config
type Config struct {
	Debug       bool
	InputPath   string
	Filename    string
	Output      *output
	VaultConfig *vault.Config
}

func New(c *Config) (*Config, error) {
	return &Config{
		Debug:       c.Debug,
		InputPath:   c.InputPath,
		Filename:    c.Filename,
		Output:      c.Output,
		VaultConfig: c.VaultConfig,
	}, nil
}

func (c *Config) Secrets() error {
	secretScraper, err := NewSecretScraper(c.VaultConfig)
	if err != nil {
		return err
	}

	var wg sync.WaitGroup

	secretScraper.Run(c.InputPath, &wg, runtime.NumCPU())
	wg.Wait()

	if len(secretScraper.Data) == 0 {
		log.Println("No secrets found")
		return nil
	}

	if err := c.ProcessOutput(secretScraper.Data); err != nil {
		return err
	}

	return nil
}

func isDir(p string) bool {
	lastChar := p[len(p)-1:]
	if lastChar != "/" {
		return false
	}
	return true
}

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

	filename := fmt.Sprintf("%s/%s.%s", c.Output.GetPath(), c.Filename, c.Output.GetEncoding())
	if ok := file.WriteFile(filename, output); !ok {
		return fmt.Errorf("failed to write %v", filename)
	}

	return nil
}

// GetPathForOutput
func GetPathForOutput(path string) string {
	if path == "" {
		path = "/tmp/vault-dump"
	}
	return vault.EnsureNoTrailingSlash(path)
}

// ProcessOutput takes action based on inputs to complete the
// desired output result
func (c *Config) ProcessOutput(m map[string]interface{}) error {
	switch c.Output.GetKind() {

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
