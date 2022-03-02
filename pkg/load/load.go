package load

import (
	"context"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"

	"github.com/dathan/go-vault-dump/pkg/file"
	"github.com/dathan/go-vault-dump/pkg/vault"
	"golang.org/x/sync/syncmap"
)

var DatabaseConnectionDetailsKey = "connection_details"

// Config
type Config struct {
	VaultConfig *vault.Config
	wg          *sync.WaitGroup
	errInfo     *errInfo
}

type errInfo struct {
	count *sync.Map
	data  *sync.Map
}

// New
func New(c *Config) (*Config, error) {
	return &Config{
		VaultConfig: c.VaultConfig,
		wg:          new(sync.WaitGroup),
		errInfo: &errInfo{
			count: new(syncmap.Map),
			data:  new(syncmap.Map),
		},
	}, nil
}

// FromFile
func (c *Config) FromFile(filepath string) error {
	ctx, cancelFunc := context.WithCancel(context.Background())

	signalChan := make(chan os.Signal, 1)
	go signalHandler(ctx, cancelFunc, signalChan)

	secrets, err := readSecretsFromFile(filepath)
	if err != nil {
		cancelFunc()
		return err
	}

	secretChan := make(chan map[string]interface{})
	c.wg.Add(1)
	go c.secretProducer(ctx, secrets, secretChan)

	for i := 0; i != 2*runtime.NumCPU(); i++ {
		c.wg.Add(1)
		go c.secretConsumer(ctx, secretChan)
	}

	c.wg.Wait()

	c.errInfo.count.Range(func(k, v interface{}) bool {
		log.Println(k, v.(int))
		return true
	})
	if err := writeFailedToFile(c.errInfo.data); err != nil {
		return err
	}

	cancelFunc()
	return nil
}

func writeFailedToFile(sm *sync.Map) error {
	failed := make(map[string]interface{})
	sm.Range(func(k, v interface{}) bool {
		failed[k.(string)] = v
		return true
	})
	if len(failed) == 0 {
		return nil
	}

	cwd, err := os.Getwd()
	if err != nil {
		return err
	}

	jsonData, err := json.Marshal(failed)
	if err != nil {
		return err
	}

	data := string(jsonData)
	filename := fmt.Sprintf("%x", sha1.Sum([]byte(data)))
	if ok := file.WriteFile(fmt.Sprintf("%v/%v.json", cwd, filename), data); !ok {
		return fmt.Errorf("failed to write file %v", filename)
	}

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

func signalHandler(ctx context.Context, cancelFunc context.CancelFunc, signalChan chan os.Signal) {
	defer close(signalChan)
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
}

func (c *Config) secretProducer(ctx context.Context, secrets map[string]interface{}, secretChan chan map[string]interface{}) {
	defer c.wg.Done()

	for p, s := range secrets {
		select {
		case <-ctx.Done():
			close(secretChan)
			return
		default:
			ignored := false
			for _, ip := range c.VaultConfig.Ignore.Paths {
				if strings.HasPrefix(p, ip) {
					ignored = true
					break
				}
			}
			for _, ik := range c.VaultConfig.Ignore.Keys {
				if strings.HasSuffix(p, ik) {
					ignored = true
					break
				}
			}

			if !ignored {
				secretChan <- map[string]interface{}{
					"k": p,
					"v": s,
				}
			}

		}
	}

	close(secretChan)
	log.Println("Completed map to channel")
}

func (c *Config) secretConsumer(ctx context.Context, secretChan chan map[string]interface{}) {
	defer c.wg.Done()
	for s := range secretChan {
		select {
		case <-ctx.Done():
			log.Println("Received signal to stop, stopping OverwriteSecret")
			return
		default:

			if s["v"] == nil {
				log.Println("secret value is nil", s["k"])
				return
			}
			secret, ok := s["v"].(map[string]interface{})
			if !ok {
				log.Println("type checking failed", s["k"])
				return
			}
			if vault.IsPolicy(s["k"].(string)) {
				name, hasName := secret["name"].(string)
				rules, hasRules := secret["rules"].(string)
				if hasName && hasRules && len(rules) > 0 {
					err := c.VaultConfig.OverwritePolicy(name, rules)
					if err != nil {
						c.handleConsumerError(err, s)
					}
				} else {
					log.Println("Warning: unhandled policy ", secret)
				}
			} else {
				if vault.IsDatabaseConfig(s["k"].(string)) {
					for kk, vv := range secret {
						if kk == DatabaseConnectionDetailsKey {
							for cdk, cdv := range vv.(map[string]interface{}) {
								secret[cdk] = cdv
							}
							delete(secret, DatabaseConnectionDetailsKey)
						}
					}
					if err := c.VaultConfig.OverwriteSecret(s["k"].(string), secret); err != nil {
						c.handleConsumerError(err, s)
					}
				}
				if err := c.VaultConfig.OverwriteSecret(s["k"].(string), secret); err != nil {
					c.handleConsumerError(err, s)
				}
			}
		}
	}
}

func (c *Config) handleConsumerError(err error, secret map[string]interface{}) {
	errSlice := strings.Split(err.Error(), ":")
	errID := strings.TrimSpace(errSlice[len(errSlice)-1])
	count, ok := c.errInfo.count.LoadOrStore(errID, 1)
	if ok {
		ec := count.(int) // cast interface to integer
		ec++              // increment
		c.errInfo.count.Store(errID, ec)
	}

	log.Println(err.Error())
	c.errInfo.data.Store(secret["k"].(string), secret["v"].(map[string]interface{}))
}
