package cmd

import (
	"fmt"
	"io/fs"
	"os"

	"github.com/dathan/go-vault-dump/pkg/aws"
	"github.com/spf13/cobra"
)

const (
	UMASK fs.FileMode = 0600
)

var (
	decrypt  bool
	destPath string
)

func init() {
	Cmd := &cobra.Command{
		Short: "Download vault bundle",
		Use:   "download [flags] s3://<bucket>/<key>",
		Args:  cobra.ExactArgs(1),
		RunE:  doDownload,
	}
	Cmd.Flags().BoolVarP(&decrypt, "decrypt", "d", false, "remove KMS encryption")
	Cmd.Flags().StringVarP(&destPath, "output", "o", "", "output path")
	rootCmd.AddCommand(Cmd)
}

func doDownload(cmd *cobra.Command, args []string) error {
	srcPath := args[0]

	data, err := aws.S3Get(srcPath)
	if err != nil {
		return err
	}

	if decrypt {
		dd, err := aws.KMSDecrypt(string(data))
		if err != nil {
			return err
		}
		data = []byte(dd)
	}

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
