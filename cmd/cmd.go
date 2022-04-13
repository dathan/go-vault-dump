package cmd

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	ignoreKeysFlag  = "ignore-keys"
	ignorePathsFlag = "ignore-paths"
	vaFlag          = "vault-addr"
	vtFlag          = "vault-token"
)

var (
	cfgFile string
	rootCmd *cobra.Command
	version = "dev" // https://goreleaser.com/environment/#using-the-mainversion
	Verbose bool
)

func exitErr(e error) {
	log.SetOutput(os.Stderr)
	log.Println(e)
	os.Exit(1)
}

func init() {
	rootCmd = &cobra.Command{
		Use: "vault-tools <subcommand> [flags]",
	}
	rootCmd.Version = version

	logSetup()
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.vault-dump/config.yaml)")
	rootCmd.PersistentFlags().String(vaFlag, "https://127.0.0.1:8200", "vault url")
	rootCmd.PersistentFlags().String(vtFlag, "", "vault token")
	rootCmd.PersistentFlags().StringSlice(ignoreKeysFlag, []string{}, "comma separated list of key names to ignore")
	rootCmd.PersistentFlags().StringSlice(ignorePathsFlag, []string{}, "comma separated list of paths to ignore")
	rootCmd.PersistentFlags().BoolVarP(&Verbose, "verbose", "v", false, "verbose output")

	viper.BindPFlag(ignorePathsFlag, rootCmd.PersistentFlags().Lookup(ignorePathsFlag))
	viper.BindPFlag(ignoreKeysFlag, rootCmd.PersistentFlags().Lookup(ignoreKeysFlag))
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

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		exitErr(err)
	}
}
