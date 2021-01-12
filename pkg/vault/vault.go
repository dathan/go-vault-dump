package vault

import (
	"errors"
	"log"
	"math/rand"
	"sync"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
	"golang.org/x/sync/syncmap"
)

// Config
type Config struct {
	Address string
	Token   string
	Client  *vaultapi.Client
	Retries int
	memo    *sync.Map
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
