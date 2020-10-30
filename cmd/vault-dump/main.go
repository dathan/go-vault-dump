package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/dathan/go-vault-dump/pkg/dump"
	vaultapi "github.com/hashicorp/vault/api"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const debugFlag = "debug"
const vaFlag = "vault-addr"
const vtFlag = "vault-token"

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
	vaultClient, err := vaultapi.NewClient(vaultapi.DefaultConfig())
	if err != nil {
		log.Println("failed vault client init: " + err.Error())
		os.Exit(1)
	}
	vaultClient.SetAddress(viper.GetString(vaFlag))
	vaultClient.SetToken(viper.GetString(vtFlag))

	config := &dump.Config{
		Debug:  viper.GetBool(debugFlag),
		Client: vaultClient,
	}
	config.SetInput(pflag.Arg(0))
	config.SetOutput(pflag.Arg(1), viper.GetString("enc"), viper.GetString("o"))

	ss := dump.SecretScraper{}
	secretScraper := ss.New(vaultClient)

	path := config.GetInput()
	secretScraper.Start(2, path)

	secretScraper.ProcessOutput(config)
}
