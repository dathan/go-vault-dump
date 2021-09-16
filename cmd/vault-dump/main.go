package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/dathan/go-vault-dump/pkg/dump"
	"github.com/dathan/go-vault-dump/pkg/vault"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	fileFlag        = "filename"
	vaFlag          = "vault-addr"
	vtFlag          = "vault-token"
	ignoreKeysFlag  = "ignore-keys"
	ignorePathsFlag = "ignore-paths"
)

var (
	cfgFile    string
	encoding   string
	kubeconfig string
	output     string
	rootCmd    *cobra.Command

	// https://goreleaser.com/environment/#using-the-mainversion
	version = "dev"
	commit  = "none"
	date    = "unknown"
	builtBy = "unknown"
)

var (
	// Verbose
	Verbose bool
)

func exitErr(e error) {
	log.SetOutput(os.Stderr)
	log.Println(e)
	os.Exit(1)
}

func init() {
	rootCmd = &cobra.Command{
		Use:   "vault-dump",
		Short: "dump secrets from Vault",
		Long:  ``,
		Args: func(cmd *cobra.Command, args []string) error {
			logSetup()
			if len(args) < 1 {
				return errors.New("Not enough arguments passed, please provide Vault path")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			vc, err := vault.NewClient(&vault.Config{
				Address: viper.GetString(vaFlag),
				Ignore: &vault.Ignore{
					Keys:  viper.GetStringSlice(ignoreKeysFlag),
					Paths: viper.GetStringSlice(ignorePathsFlag),
				},
				Retries: 5,
				Token:   viper.GetString(vtFlag),
			})
			if err != nil {
				return err
			}

			outputPath := ""
			if len(args) > 1 {
				outputPath = args[1]
			}
			outputPath = dump.GetPathForOutput(outputPath)

			output, err := dump.NewOutput(
				outputPath,
				encoding,
				output,
			)
			if err != nil {
				return err
			}

			outputFilename := viper.GetString(fileFlag)

			dumper, err := dump.New(&dump.Config{
				Debug:       Verbose,
				InputPath:   args[0],
				Filename:    outputFilename,
				Output:      output,
				VaultConfig: vc,
			})
			if err != nil {
				return err
			}

			if err := dumper.Secrets(); err != nil {
				return err
			}

			return nil
		},
	}

	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.vault-dump/config.yaml)")
	rootCmd.PersistentFlags().String(vaFlag, "https://127.0.0.1:8200", "vault url")
	rootCmd.PersistentFlags().String(vtFlag, "", "vault token")
	rootCmd.PersistentFlags().String(fileFlag, "vault-dump", "output filename (an extension will be added)")
	rootCmd.PersistentFlags().StringSlice(ignoreKeysFlag, []string{}, "comma separated list of key names to ignore")
	rootCmd.PersistentFlags().StringSlice(ignorePathsFlag, []string{}, "comma separated list of paths to ignore")
	rootCmd.PersistentFlags().StringVarP(&encoding, "encoding", "e", "json", "encoding type [json, yaml]")
	rootCmd.PersistentFlags().StringVarP(&output, "output", "o", "file", "output type, [stdout, file (default)]")
	rootCmd.PersistentFlags().StringVarP(&kubeconfig, "kubeconfig", "k", "", "location of kube config file")
	rootCmd.PersistentFlags().BoolVarP(&Verbose, "verbose", "v", false, "verbose output")
	rootCmd.Version = version

	viper.BindPFlag(ignoreKeysFlag, rootCmd.PersistentFlags().Lookup(ignoreKeysFlag))
	viper.BindPFlag(ignorePathsFlag, rootCmd.PersistentFlags().Lookup(ignorePathsFlag))
	viper.BindPFlag(fileFlag, rootCmd.PersistentFlags().Lookup(fileFlag))
	viper.BindPFlag(vaFlag, rootCmd.PersistentFlags().Lookup(vaFlag))
	viper.BindPFlag(vtFlag, rootCmd.PersistentFlags().Lookup(vtFlag))
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile) // Use config file from the flag.
	} else {
		viper.SetConfigName("config")            // name of config file (without extension)
		viper.SetConfigType("yaml")              // REQUIRED if the config file does not have the extension in the name
		viper.AddConfigPath("/etc/vault-dump/")  // path to look for the config file in
		viper.AddConfigPath("$HOME/.vault-dump") // call multiple times to add many search paths
	}

	if err := viper.ReadInConfig(); err != nil { // Handle errors reading the config file
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			// Config file was found but another error was produced
			exitErr(fmt.Errorf("fatal error config file: %v", err))
		}
	}
	viper.SetEnvPrefix("VAULT_DUMP")
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
