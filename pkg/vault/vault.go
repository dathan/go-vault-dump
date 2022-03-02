package vault

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"runtime"
	"strings"
	"sync"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
	"golang.org/x/sync/syncmap"
)

const (
	bufsize = 1000
)

var VaultDatabaseConfigPrefix = []string{"/database/config/"}
var VaultPolicyPrefix = []string{"/sys/policy/"}
var VaultPolicyProtected = []string{"/sys/policy/default", "/sys/policy/root"}

// Config
type Config struct {
	Address string
	Token   string
	Client  *vaultapi.Client
	Retries int
	Ignore  *Ignore
	memo    *sync.Map
}

// Ignore
type Ignore struct {
	Keys  []string
	Paths []string
}

// PurgeContext
type PurgeContext struct {
	client *Config
	wait   *sync.WaitGroup
	tasks  *chan string
	done   bool
}

// NewClient
func NewClient(vc *Config) (*Config, error) {
	vaultClient, err := vaultapi.NewClient(vaultapi.DefaultConfig())
	if err != nil {
		return &Config{}, errors.New("failed vault client init: " + err.Error())
	}
	vaultClient.SetAddress(vc.Address)
	vaultClient.SetToken(vc.Token)
	vc.Client = vaultClient
	vc.memo = new(syncmap.Map)

	return vc, nil
}

// updateSecret
func (vc *Config) updateSecret(path string, secret map[string]interface{}) (bool, error) {
	// TODO decide if we should be idempotent here
	if _, err := vc.Client.Logical().Write(path, secret); err != nil {
		return false, err
	}
	return true, nil
}

// OverwriteSecret
func (vc *Config) OverwriteSecret(path string, secret map[string]interface{}) error {
	rand.Seed(time.Now().UTC().UnixNano())
	path = SanitizePath(path)

	var err error // required for scope of other vars
	retries := 0
	ok := false
	for !ok {
		path, secret, err = vc.updateIfKVv2(path, secret)
		if err == nil {
			ok = true
			continue
		}
		if retries > 0 {
			log.Printf("failed, try number %v with error %v\n", retries+1, err.Error())
		}
		time.Sleep(time.Duration(rand.Int31n(1000)) * time.Millisecond)
		retries++
		if vc.Retries == 0 {
			continue
		}
		if retries > vc.Retries {
			return err
		}
	}

	retries = 0 // reset value
	ok = false  // reset value
	for !ok {
		ok, err = vc.updateSecret(path, secret)
		if err == nil {
			if retries > 1 {
				log.Printf("success, try number %v for %v\n", retries, path)
			}
			continue
		} else {
			if retries > 0 {
				log.Printf("failed, try number %v with error %v\n", retries+1, err.Error())
			}
		}

		time.Sleep(time.Duration(rand.Int31n(1000)) * time.Millisecond)
		retries++
		if vc.Retries == 0 {
			continue
		}
		if retries > vc.Retries {
			return err
		}
	}

	// log.Println("wrote secret to:", path)
	return nil
}

// OverwritePolicy
func (vc *Config) OverwritePolicy(name string, rules string) error {
	var err error
	retries := 0
	ok := false
	for !ok {
		//path, secret, err = vc.updateIfKVv2(path, secret)
		err = vc.Client.Sys().PutPolicy(name, rules)

		if err == nil {
			log.Printf("Policy updated: %s", name)
			return nil
		}
		if retries > 0 {
			log.Printf("failed, try number %v with error %v\n", retries+1, err.Error())
		}
		time.Sleep(time.Duration(rand.Int31n(1000)) * time.Millisecond)
		retries++
		if vc.Retries == 0 {
			continue
		}
		if retries > vc.Retries {
			return err
		}
	}
	return errors.New("To dream the impossible dream, to reach the unreachable code.")
}

// DeletePolicy
func (vc *Config) DeletePolicy(name string) error {
	r := vc.Client.NewRequest("DELETE", fmt.Sprintf("/v1/%s", EnsureNoLeadingSlash(name)))
	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()
	resp, err := vc.Client.RawRequestWithContext(ctx, r)
	if err == nil {
		defer resp.Body.Close()
	}
	return err
}

// ListPolicies
func (vc *Config) ListPolicies() ([]string, error) {
	return vc.Client.Sys().ListPolicies()
}

// ListSecrets
func (vc *Config) ListSecrets(key string) ([]string, error) {
	list, err := vc.Client.Logical().List(key)
	if err != nil {
		return nil, err
	}
	if list != nil && list.Data != nil {
		keys := list.Data["keys"].([]interface{})
		resp := make([]string, len(keys))
		for ii, kk := range keys {
			resp[ii] = kk.(string)
		}
		return resp, nil
	}
	return make([]string, 0), nil
}

// DeleteSecret
func (vc *Config) DeleteSecret(key string) error {
	_, err := vc.Client.Logical().Delete(key)
	if err != nil {
		return err
	}
	return nil
}

// PurgePaths
func (vc *Config) PurgePaths(paths []string) error {
	nprocs := runtime.NumCPU() * 2
	tasks := make(chan string, bufsize)
	var wait sync.WaitGroup

	errors := make([]error, 0)
	cxt := PurgeContext{
		client: vc,
		wait:   &wait,
		tasks:  &tasks,
		done:   false,
	}
	for _, path := range paths {
		wait.Add(1)
		tasks <- path
	}
	for ii := 0; ii < nprocs; ii++ {
		go func() {
			for {
				if cxt.done {
					break
				}
				select {
				case key := <-*cxt.tasks:
					err := purgeKey(key, &cxt)
					if err != nil {
						errors = append(errors, err)
					}
					cxt.wait.Done()
				default:
					time.Sleep(10 * time.Millisecond)
				}
			}
		}()
	}
	wait.Wait()
	cxt.done = true

	if len(errors) > 0 {
		log.Println("Purge completed with errors:")
		for _, err := range errors {
			log.Println(err)
		}
	} else {
		log.Println("Purge complete")
	}
	return nil
}

// IsDatabaseConfig
func IsDatabaseConfig(key string) bool {
	for _, prefix := range VaultDatabaseConfigPrefix {
		if strings.HasPrefix(key, EnsureNoTrailingSlash(prefix)) {
			return true
		}
	}
	return false
}
// IsPolicy
func IsPolicy(key string) bool {
	for _, prefix := range VaultPolicyPrefix {
		if strings.HasPrefix(key, EnsureNoTrailingSlash(prefix)) {
			return true
		}
	}
	return false
}

// IsPolicyRoot
func IsPolicyRoot(key string) bool {
	key = EnsureNoTrailingSlash(key)
	for _, prefix := range VaultPolicyPrefix {
		if key == EnsureNoTrailingSlash(prefix) {
			return true
		}
	}
	return false
}

// purgeKey
func purgeKey(key string, cxt *PurgeContext) error {
	if IsPolicy(key) {
		if IsPolicyRoot(key) {
			policies, err := cxt.client.ListPolicies()
			if err != nil {
				return fmt.Errorf("Error enumerating %s: %s", key, err)
			}
			for _, kk := range policies {
				cxt.wait.Add(1)
				*cxt.tasks <- fmt.Sprintf("%s/%s", EnsureNoTrailingSlash(key), kk)
			}
		} else {
			for _, kk := range VaultPolicyProtected {
				if key == kk {
					return nil
				}
			}
			err := cxt.client.DeletePolicy(key)
			if err != nil {
				return fmt.Errorf("Error deleting %s: %s", key, err)
			}
			log.Println(key)
		}
	} else {
		key = EnsureNoTrailingSlash(key)
		children, _ := cxt.client.ListSecrets(EnsureTrailingSlash(key))
		cxt.wait.Add(len(children))
		go func() {
			for _, kk := range children {
				*cxt.tasks <- fmt.Sprintf("%s/%s", key, kk)
			}
		}()

		err := cxt.client.DeleteSecret(key)
		if err == nil {
			log.Println(key)
		}
	}
	return nil
}
