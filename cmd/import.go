package cmd

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/dathan/go-vault-dump/pkg/aws"
	"github.com/dathan/go-vault-dump/pkg/file"
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

	importCmd.Flags().BoolVarP(&Brute, "brute", "", false, "retry failed indefinitely")
	importCmd.Flags().ParseErrorsWhitelist.UnknownFlags = true

}

func importVault(cmd *cobra.Command, args []string) error {

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

	filepath := args[0]
	fromS3 := len(filepath) > 5 && filepath[:5] == "s3://"
	tmpDir := ""

	if fromS3 {
		encrypted, err := aws.S3Get(filepath)
		if err != nil {
			return err
		}
		plaintext, err := aws.KMSDecrypt(string(encrypted))
		if err != nil {
			return err
		}
		tmpDir, err = ioutil.TempDir("", "vault-dump-*")
		if err != nil {
			return err
		}

		defer os.RemoveAll(tmpDir)
		
		pathslices := strings.Split(filepath, "/")
		filename := pathslices[len(pathslices)-1]
		filepath = fmt.Sprintf("%s/%s", vault.EnsureNoTrailingSlash(tmpDir), filename)
		ok := file.WriteFile(filepath, plaintext)
		if !ok {
			os.RemoveAll(tmpDir)
			return errors.New(fmt.Sprintf("Error writing %s", filepath))
		}
	}
	
	if err := loader.FromFile(filepath); err != nil {
		return err
	}

	return nil
}
