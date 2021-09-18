package cmd

import (
	"github.com/dathan/go-vault-dump/pkg/load"
	"github.com/dathan/go-vault-dump/pkg/vault"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	Brute     bool
	importCmd *cobra.Command
)

func init() {
	importCmd = &cobra.Command{
		Use:   "import [flags] <filename>",
		Short: "import secrets to Vault",
		Args:  cobra.ExactArgs(1),
		RunE:  importVault,
	}
	rootCmd.AddCommand(importCmd)

	importCmd.Flags().String(vaFlag, "https://127.0.0.1:8200", "vault url")
	importCmd.Flags().String(vtFlag, "", "vault token")
	importCmd.Flags().StringSlice(ignoreKeysFlag, []string{}, "comma separated list of key names to ignore")
	importCmd.Flags().StringSlice(ignorePathsFlag, []string{}, "comma separated list of paths to ignore")
	importCmd.Flags().BoolVarP(&Verbose, "verbose", "v", false, "verbose output")
	importCmd.Flags().BoolVarP(&Brute, "brute", "", false, "retry failed indefinitely")
	importCmd.Flags().ParseErrorsWhitelist.UnknownFlags = true

}

func importVault(cmd *cobra.Command, args []string) error {

	//let's take over from rootCmd
	viper.BindPFlag(ignoreKeysFlag, importCmd.Flags().Lookup(ignoreKeysFlag))
	viper.BindPFlag(ignorePathsFlag, importCmd.Flags().Lookup(ignorePathsFlag))
	viper.BindPFlag(vaFlag, importCmd.Flags().Lookup(vaFlag))
	viper.BindPFlag(vtFlag, importCmd.Flags().Lookup(vtFlag))

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

	filename := args[0]

	if len(filename) > 5 && filename[:5] == "s3://" {
		//TODO
	}

	if err := loader.FromFile(filename); err != nil {
		return err
	}

	return nil
}
