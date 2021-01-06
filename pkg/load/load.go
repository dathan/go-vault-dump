package load

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"

	"github.com/dathan/go-vault-dump/pkg/vault"
	"golang.org/x/sync/syncmap"
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

	errCount := new(syncmap.Map)
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
						errSlice := strings.Split(err.Error(), ":")
						errID := strings.TrimSpace(errSlice[len(errSlice)-1])
						count, ok := errCount.LoadOrStore(errID, 1)
						if ok {
							ec := count.(int) // cast interface to integer
							ec++              // increment
							errCount.Store(errID, ec)
						}

						log.Println(err.Error())
					}
				}

			}
		}(ctx)
	}

	c.wg.Wait()
	errCount.Range(func(k, v interface{}) bool {
		log.Println(k, v.(int))
		return true
	})
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
