package main

import (
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

var (
	debug bool
	wg    sync.WaitGroup
)

func init() {
	pflag.String(vaFlag, "https://127.0.0.1:8200", "vault url")
	pflag.String(vtFlag, "", "vault token")
	pflag.String("enc", "yaml", "encoding type [json, yaml]")
	pflag.String("o", "stdout", "output type, [stdout, file]")
	pflag.Bool("debug", false, "enables verbose messages")
	pflag.CommandLine.ParseErrorsWhitelist.UnknownFlags = true
	pflag.Parse()
	viper.BindPFlags(pflag.CommandLine)
	viper.AutomaticEnv()

}

func main() {

	if viper.IsSet(debugFlag) {
		dump.Debug = true
	}

	config := vaultapi.DefaultConfig()
	client, err := vaultapi.NewClient(config)
	dump.CheckErr(err, "failed vault client init")

	if viper.IsSet(vaFlag) {
		dump.DebugMsg("flag set: " + vaFlag)
		client.SetAddress(viper.GetString(vaFlag))
	}

	if viper.IsSet(vtFlag) {
		dump.DebugMsg("flag set: " + vtFlag)
		client.SetToken(viper.GetString(vtFlag))
	}

	inputPath := dump.GetPathFromInput(client, pflag.Arg(0))
	outputPath := dump.GetPathForOutput(pflag.Arg(1))

	var sm sync.Map
	dump.FindVaultSecrets(client, inputPath, &sm, &wg)
	wg.Wait()

	dump.ProcessOutput(&sm, viper.GetString("enc"), viper.GetString("o"), inputPath, outputPath)

}
