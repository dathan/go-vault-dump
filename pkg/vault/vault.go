package vault

import (
	"errors"
	"log"

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

// OverwriteSecret
func (vc *Config) OverwriteSecret(path string, secret map[string]interface{}) error {
	path = SanitizePath(path)

	path, secret, err := updateIfKVv2(vc.Client, path, secret)
	if err != nil {
		return err
	}

	// TODO decide if we should be idempotent here
	if _, err := vc.Client.Logical().Write(path, secret); err != nil {
		return err
	}

	log.Println("wrote secret to:", path)
	return nil
}
