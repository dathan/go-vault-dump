package cmd

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/dathan/go-vault-dump/pkg/aws"
	"github.com/spf13/cobra"
)

var (
	keyArn string
)

func init() {
	Cmd := &cobra.Command{
		Short: "Encrypt vault bundle",
		Use:   "encrypt [flags] <path>",
		Args:  cobra.ExactArgs(1),
		RunE:  doEncrypt,
	}
	Cmd.Flags().StringVarP(&destPath, "output", "o", "", "output path")
	Cmd.Flags().StringVarP(&keyArn, "key", "k", "", "KMS key ARN")
	rootCmd.AddCommand(Cmd)
}

func doEncrypt(cmd *cobra.Command, args []string) error {
	srcPath := args[0]

	if keyArn == "" {
		return errors.New("error: KMS key ARN must be specified")
	}

	plaintext, err := ioutil.ReadFile(srcPath)
	if err != nil {
		return err
	}

	ciphertext, err := aws.KMSEncrypt(string(plaintext), keyArn)
	if err != nil {
		return err
	}

	if destPath == "" {
		fmt.Print(string(ciphertext))
	} else {

		ff, err := os.Create(destPath)
		if err != nil {
			return err
		}

		err = ff.Chmod(UMASK)
		if err != nil {
			return err
		}

		data := []byte(ciphertext)
		_, err = ff.Write(data)
		if err != nil {
			return err
		}
	}

	return nil
}
