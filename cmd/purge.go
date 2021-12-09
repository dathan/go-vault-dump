package cmd

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/dathan/go-vault-dump/pkg/vault"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	warnTime = 10
	warnText = `
*** DANGER ZONE ***

This command will PERMANENTLY DELETE DATA from %s

Pausing for %d seconds...
`
)

var (
	force    bool
	purgeCmd *cobra.Command
)

func init() {
	purgeCmd = &cobra.Command{
		Use:   "purge [flags] /vault/path[,...]",
		Short: "Recursively delete one or more paths from vault",
		Args:  cobra.ExactArgs(1),
		RunE:  purgeVault,
	}
	purgeCmd.Flags().BoolVar(&force, "force", false, "Skip confirmation prompt")

	rootCmd.AddCommand(purgeCmd)
}

func purgeVault(cmd *cobra.Command, args []string) error {

	vaultAddress := viper.GetString(vaFlag)
	if vaultAddress == "" {
		log.Fatalf("--%s not specified; exiting", vaFlag)
	}
	vaultToken := viper.GetString(vtFlag)
	if vaultToken == "" {
		log.Fatalf("--%s not specified; exiting", vtFlag)
	}

	// ensure we don't silently accept flags we aren't going to honor
	if len(viper.GetStringSlice(ignoreKeysFlag)) > 0 {
		log.Fatalf("--%s is not valid for purge command; exiting", ignoreKeysFlag)
	}
	if len(viper.GetStringSlice(ignorePathsFlag)) > 0 {
		log.Fatalf("--%s is not valid for purge command; exiting", ignorePathsFlag)
	}

	vc, err := vault.NewClient(&vault.Config{
		Address: vaultAddress,
		Token:   vaultToken,
	})
	if err != nil {
		return err
	}

	fmt.Printf(warnText, vaultAddress, warnTime)
	time.Sleep(warnTime * time.Second)

	if !force {
		fmt.Println("Press 'Enter' to continue")
		bufio.NewReader(os.Stdin).ReadBytes('\n')
	}

	return vc.PurgePaths(strings.Split(args[0], ","))
}
