package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/dathan/go-vault-dump/pkg/load"
	"github.com/dathan/go-vault-dump/pkg/vault"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	vaFlag          = "vault-addr"
	vtFlag          = "vault-token"
	ignoreKeysFlag  = "ignore-keys"
	ignorePathsFlag = "ignore-paths"
)

var (
	cfgFile string
	rootCmd *cobra.Command

	// Brute global var
	Brute bool
	// Verbose global var
	Verbose bool

	// https://goreleaser.com/environment/#using-the-mainversion
	version = "dev"
	commit  = "none"
	date    = "unknown"
	builtBy = "unknown"
)

func exitErr(e error) {
	log.SetOutput(os.Stderr)
	log.Println(e)
	os.Exit(1)
}

func init() {
	rootCmd = &cobra.Command{
		Use:   "vault-import",
		Short: "import secrets to Vault",
		Long:  `Imports multiple secrets from a file created by vault-dump`,
		Args: func(cmd *cobra.Command, args []string) error {
			logSetup() // behavior suggests that RunE inherits scope from Args
			// validate input
			if len(args) < 1 {
				return errors.New("Not enough arguments passed, please provide path to the file")
			}
			if _, err := os.Stat(args[0]); err != nil {
				return err
			}

			if viper.GetString(vaFlag) == "" {
				return errors.New(vaFlag + " must be set")
			}
			if viper.GetString(vtFlag) == "" {
				return errors.New(vtFlag + " must be set")
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			retries := 5
			if Brute {
				retries = 0
			}
			vc, err := vault.NewClient(&vault.Config{
				Address: viper.GetString(vaFlag),
				Retries: retries,
				Token:   viper.GetString(vtFlag),
				Ignore: &vault.Ignore{
					Keys:  viper.GetStringSlice(ignoreKeysFlag),
					Paths: viper.GetStringSlice(ignorePathsFlag),
				},
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
				return err
			}

			return nil
		},
	}

	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is ./config.yaml)")
	rootCmd.PersistentFlags().String(vaFlag, "https://127.0.0.1:8200", "vault url")
	rootCmd.PersistentFlags().String(vtFlag, "", "vault token")
	rootCmd.PersistentFlags().StringSlice(ignoreKeysFlag, []string{}, "comma separated list of key names to ignore")
	rootCmd.PersistentFlags().StringSlice(ignorePathsFlag, []string{}, "comma separated list of paths to ignore")
	rootCmd.PersistentFlags().BoolVarP(&Verbose, "verbose", "v", false, "verbose output")
	rootCmd.PersistentFlags().BoolVarP(&Brute, "brute", "", false, "retry failed indefinitely")
	rootCmd.Flags().ParseErrorsWhitelist.UnknownFlags = true
	rootCmd.Version = version

	viper.BindPFlag(ignoreKeysFlag, rootCmd.PersistentFlags().Lookup(ignoreKeysFlag))
	viper.BindPFlag(ignorePathsFlag, rootCmd.PersistentFlags().Lookup(ignorePathsFlag))
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

func logSetup() {
	log.SetFlags(0)
	if Verbose {
		log.SetFlags(log.LstdFlags | log.Lshortfile)
	}
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		exitErr(err)
	}
}
