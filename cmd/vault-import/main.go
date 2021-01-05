package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/dathan/go-vault-dump/pkg/load"
	"github.com/dathan/go-vault-dump/pkg/vault"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const (
	debugFlag = "debug"
	vaFlag    = "vault-addr"
	vtFlag    = "vault-token"
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

			// go func() {
			if err := loader.FromFile(args[0]); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			// }()

			// TODO
			// signalChan := make(chan os.Signal, 1)
			// signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
			// <-signalChan
			// loader.Shutdown(context.Background())
			return nil
		},
	}
)

func init() {
	l := len(os.Args)
	switch {
	case l < 2:
		fmt.Fprintln(os.Stderr, errors.New("Not enough arguments passed, please provide path to the file"))
		os.Exit(1)
	case l == 2:
		if _, err := os.Stat(os.Args[1]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	default:
		fmt.Fprintln(os.Stderr, errors.New("Too many arguments passed, using the first"))
	}
}

func main() {
	pflag.String(vaFlag, "https://127.0.0.1:8200", "vault url")
	pflag.String(vtFlag, "", "vault token")
	pflag.String("kubeconfig", "", "location of kube config file")
	pflag.Bool(debugFlag, false, "enables verbose messages")
	pflag.CommandLine.ParseErrorsWhitelist.UnknownFlags = true
	pflag.Parse()
	viper.BindPFlags(pflag.CommandLine)
	viper.SetConfigName("config")                // name of config file (without extension)
	viper.SetConfigType("yaml")                  // REQUIRED if the config file does not have the extension in the name
	viper.AddConfigPath("/etc/vault-import/")    // path to look for the config file in
	viper.AddConfigPath("$HOME/.vault-import")   // call multiple times to add many search paths
	viper.AddConfigPath(".")                     // optionally look for config in the working directory
	if err := viper.ReadInConfig(); err != nil { // Handle errors reading the config file
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			// Config file was found but another error was produced
			fmt.Fprintln(os.Stderr, fmt.Errorf("fatal error config file: %v", err))
			os.Exit(1)
		}
	}

	viper.SetEnvPrefix("VAULT_IMPORT")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))
	viper.AutomaticEnv()

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
