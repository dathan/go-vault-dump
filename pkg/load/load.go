package load

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/dathan/go-vault-dump/pkg/vault"
)

// Config
type Config struct {
	VaultConfig *vault.Config
	ch          chan os.Signal
	wg          *sync.WaitGroup
}

// New
func New(c *Config) (*Config, error) {
	return &Config{
		VaultConfig: c.VaultConfig,
		ch:          make(chan os.Signal, 1),
		wg:          new(sync.WaitGroup),
	}, nil
}

// FromFile
func (c *Config) FromFile(filepath string) error {
	defer close(c.ch)

	signalChan := make(chan os.Signal, 1)
	go func() {
		defer close(signalChan)
		signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
		<-signalChan
		c.Shutdown(context.Background())
	}()

	secrets, err := readSecretsFromFile(filepath)
	if err != nil {
		return err
	}

	secretChan := make(chan map[string]interface{})
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		defer close(secretChan)

		for p, s := range secrets {
			select {
			case <-c.ch:
				break
			default:
				secretChan <- map[string]interface{}{
					"k": p,
					"v": s,
				}
			}
		}

	}()

	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		for s := range secretChan {
			select {
			case <-c.ch:
				break
			default:
				if err := c.VaultConfig.OverwriteSecret(s["k"].(string), s["v"].(map[string]interface{})); err != nil {
					fmt.Println(err.Error())
				}
			}

		}
	}()

	c.wg.Wait()
	return nil
}

// Shutdown
func (c *Config) Shutdown(ctx context.Context) {
	c.ch <- syscall.SIGTERM // or do I just close(c.ch)
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
