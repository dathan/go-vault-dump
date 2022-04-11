package cmd

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/dathan/go-vault-dump/pkg/aws"
	"github.com/spf13/cobra"
)

func init() {
	Cmd := &cobra.Command{
		Short: "Decrypt vault bundle",
		Use:   "decrypt [flags] <path>",
		Args:  cobra.ExactArgs(1),
		RunE:  doDecrypt,
	}
	Cmd.Flags().StringVarP(&destPath, "output", "o", "", "output path")
	rootCmd.AddCommand(Cmd)
}

func doDecrypt(cmd *cobra.Command, args []string) error {
	srcPath := args[0]

	data, err := ioutil.ReadFile(srcPath)
	if err != nil {
		return err
	}

	dd, err := aws.KMSDecrypt(string(data))
	if err != nil {
		return err
	}
	data = []byte(dd)

	if destPath == "" {
		fmt.Print(string(data))
	} else {

		ff, err := os.Create(destPath)
		if err != nil {
			return err
		}

		err = ff.Chmod(UMASK)
		if err != nil {
			return err
		}

		_, err = ff.Write(data)
		if err != nil {
			return err
		}

	}

	return nil
}
