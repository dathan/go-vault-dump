package load

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"

	"github.com/dathan/go-vault-dump/pkg/vault"
)

// Config
type Config struct {
	VaultConfig *vault.Config
	wg          *sync.WaitGroup
}

// New
func New(c *Config) (*Config, error) {
	return &Config{
		VaultConfig: c.VaultConfig,
		wg:          new(sync.WaitGroup),
	}, nil
}

// FromFile
func (c *Config) FromFile(filepath string) error {
	ctx, cancelFunc := context.WithCancel(context.Background())

	signalChan := make(chan os.Signal, 1)
	go func(ctx context.Context) {
		defer close(signalChan)
		log.Println("Listening for signals")
		signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

		select {
		case <-ctx.Done():
			break
		case s := <-signalChan:
			if s != nil {
				log.Println("Caught signal:", s)
			}
		}
		cancelFunc()
	}(ctx)

	secrets, err := readSecretsFromFile(filepath)
	if err != nil {
		cancelFunc()
		return err
	}

	secretChan := make(chan map[string]interface{})
	c.wg.Add(1)
	go func(ctx context.Context) {
		defer c.wg.Done()

		for p, s := range secrets {
			select {
			case <-ctx.Done():
				close(secretChan)
				return
			default:
				secretChan <- map[string]interface{}{
					"k": p,
					"v": s,
				}
			}
		}

		close(secretChan)
		log.Println("Completed map to channel")
	}(ctx)

	for i := 0; i != 2*runtime.NumCPU(); i++ {
		c.wg.Add(1)
		go func(ctx context.Context) {
			defer c.wg.Done()
			for s := range secretChan {
				select {
				case <-ctx.Done():
					log.Println("Received signal to stop, stopping OverwriteSecret")
					return
				default:
					if err := c.VaultConfig.OverwriteSecret(s["k"].(string), s["v"].(map[string]interface{})); err != nil {
						log.Println(err.Error())
					}
				}

			}
		}(ctx)
	}

	c.wg.Wait()
	cancelFunc()
	return nil
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
