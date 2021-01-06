package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/dathan/go-vault-dump/pkg/load"
	"github.com/dathan/go-vault-dump/pkg/vault"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	vaFlag = "vault-addr"
	vtFlag = "vault-token"
)

var (
	cfgFile string
	rootCmd = &cobra.Command{
		Use:   "vault-import",
		Short: "import secrets to Vault",
		Long:  `Imports multiple secrets from a file created by vault-dump`,
		RunE: func(cmd *cobra.Command, args []string) error {
			vc, err := vault.NewClient(&vault.Config{
				Address: viper.GetString(vaFlag),
				Token:   viper.GetString(vtFlag),
			})
			if err != nil {
				return err
			}

			loader, err := load.New(
				&load.Config{
					VaultConfig: vc,
				},
			)
			if err != nil {
				return err
			}

			if err := loader.FromFile(args[0]); err != nil {
				exitErr(err)
			}

			return nil
		},
	}
	// Verbose global var
	Verbose bool
)

func exitErr(e error) {
	fmt.Fprintln(os.Stderr, e)
	os.Exit(1)
}

func init() {
	l := len(os.Args)
	switch {
	case l < 2:
		exitErr(errors.New("Not enough arguments passed, please provide path to the file"))
	case l == 2:
		if _, err := os.Stat(os.Args[1]); err != nil {
			exitErr(err)
		}
	default:
		fmt.Fprintln(os.Stderr, errors.New("Too many arguments passed, using the first"))
	}

	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is ./config.yaml)")
	rootCmd.PersistentFlags().String(vaFlag, "https://127.0.0.1:8200", "vault url")
	rootCmd.PersistentFlags().String(vtFlag, "", "vault token")
	rootCmd.PersistentFlags().BoolVarP(&Verbose, "verbose", "v", false, "verbose output")

	// pflag.CommandLine.ParseErrorsWhitelist.UnknownFlags = true
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile) // Use config file from the flag.
	} else {
		viper.SetConfigName("config")              // name of config file (without extension)
		viper.SetConfigType("yaml")                // REQUIRED if the config file does not have the extension in the name
		viper.AddConfigPath("/etc/vault-import/")  // path to look for the config file in
		viper.AddConfigPath("$HOME/.vault-import") // call multiple times to add many search paths
		viper.AddConfigPath(".")                   // optionally look for config in the working directory
	}

	if err := viper.ReadInConfig(); err != nil { // Handle errors reading the config file
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			// Config file was found but another error was produced
			exitErr(fmt.Errorf("fatal error config file: %v", err))
		}
	}

	viper.SetEnvPrefix("VAULT_IMPORT")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))
	viper.AutomaticEnv()
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		exitErr(err)
	}
}
