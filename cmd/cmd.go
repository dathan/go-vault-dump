package cmd

import (
	"log"
	"os"

	"github.com/spf13/cobra"
)

var (
	rootCmd *cobra.Command
	version = "dev" // https://goreleaser.com/environment/#using-the-mainversion
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
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		exitErr(err)
	}
}
