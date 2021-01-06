package vault

import (
	"errors"
	"log"
	"math/rand"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

// Config
type Config struct {
	Address string
	Token   string
	Client  *vaultapi.Client
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
	path = SanitizePath(path)

	path, secret, err := updateIfKVv2(vc.Client, path, secret)
	if err != nil {
		return err
	}

	for i := 1; i < 6; i++ {
		ok, err := vc.updateSecret(path, secret)
		if ok {
			break
		}
		if i == 5 && err != nil {
			return err
		}

		time.Sleep(time.Duration(rand.Int31n(60)) * time.Second)
	}

	log.Println("wrote secret to:", path)
	return nil
}
