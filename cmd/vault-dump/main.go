package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"sync"

	"github.com/dathan/go-vault-dump/pkg/dump"
	vaultapi "github.com/hashicorp/vault/api"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const debugFlag = "debug"
const vaFlag = "vault-addr"
const vtFlag = "vault-token"

/**
 * Auth with VAULT using common environment flags
 * List all the keys
 * recursively print out the values for each key
 */

func init() {
	pflag.String(vaFlag, "https://127.0.0.1:8200", "vault url")
	pflag.String(vtFlag, "", "vault token")
	pflag.String("enc", "yaml", "encoding type [json, yaml]")
	pflag.String("o", "stdout", "output type, [stdout, file]")
	pflag.String("kc", "", "location of kube config file")
	pflag.Bool(debugFlag, false, "enables verbose messages")
	pflag.CommandLine.ParseErrorsWhitelist.UnknownFlags = true
	pflag.Parse()
	viper.BindPFlags(pflag.CommandLine)
	viper.SetConfigName("config")            // name of config file (without extension)
	viper.SetConfigType("yaml")              // REQUIRED if the config file does not have the extension in the name
	viper.AddConfigPath("/etc/vault-dump/")  // path to look for the config file in
	viper.AddConfigPath("$HOME/.vault-dump") // call multiple times to add many search paths
	viper.AddConfigPath(".")                 // optionally look for config in the working directory
	err := viper.ReadInConfig()              // Find and read the config file
	if err != nil {                          // Handle errors reading the config file
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			// Config file was found but another error was produced
			panic(fmt.Errorf("fatal error config file: %s", err))
		}
	}
	viper.SetEnvPrefix("VAULT_DUMP")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))
	viper.AutomaticEnv()

}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	client, err := vaultapi.NewClient(vaultapi.DefaultConfig())
	if err != nil {
		log.Println("failed vault client init: " + err.Error())
		os.Exit(1)
	}
	config := &dump.Config{
		Debug:  viper.GetBool(debugFlag),
		Client: client,
	}

	config.Client.SetAddress(viper.GetString(vaFlag))
	config.Client.SetToken(viper.GetString(vtFlag))
	config.SetInput(pflag.Arg(0))
	config.SetOutput(pflag.Arg(1), viper.GetString("enc"), viper.GetString("o"))

	var (
		sm sync.Map
		wg sync.WaitGroup
	)
	m := make(map[interface{}]interface{})
	if err := dump.FindVaultSecrets2(config, config.GetInput(), m, &wg); err != nil {
		log.Println(err.Error())
		os.Exit(1)
	}
	wg.Wait()

	vo, _ := dump.ValidateOutputType(viper.GetString("o"))
	switch vo {
	case "k8s":
		if err := dump.ToKube(config, &sm); err != nil {
			log.Println(err.Error())
			os.Exit(1)
		}
	default:
		// dump.ProcessOutput(config, m)
		dump.Output(config, m)
	}
}
