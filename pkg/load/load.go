package load

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"syscall"

	"github.com/dathan/go-vault-dump/pkg/vault"
)

// Config
type Config struct {
	VaultConfig *vault.Config
	ch          chan os.Signal
}

// New
func New(c *Config) (*Config, error) {

	return &Config{
		VaultConfig: c.VaultConfig,
		ch:          make(chan os.Signal, 1),
	}, nil
}

// FromFile
func (c *Config) FromFile(filepath string) error {
	secrets, err := readSecretsFromFile(filepath)
	if err != nil {
		return err
	}

	for p, s := range secrets {
		select {
		case <-c.ch:
			return nil
		default:
			if err := c.VaultConfig.OverwriteSecret(p, s.(map[string]interface{})); err != nil {
				fmt.Println(err.Error())
			}
		}

	}

	return nil
}

// Shutdown TODO
func (c *Config) Shutdown(ctx context.Context) {
	c.ch <- syscall.SIGINT

}

// readSecretsFromFile returns a map from the given json file
func readSecretsFromFile(filepath string) (map[string]interface{}, error) {
	data, err := ioutil.ReadFile(filepath)
	if err != nil {
		return map[string]interface{}{}, err
	}

	d := make(map[string]interface{})
	if err = json.Unmarshal(data, &d); err != nil {
		return map[string]interface{}{}, err
	}

	return d, nil
}
