package cmd

import (
	"errors"
	"io/ioutil"

	"github.com/dathan/go-vault-dump/pkg/aws"
	"github.com/spf13/cobra"
)

func init() {
	Cmd := &cobra.Command{
		Short: "Upload vault bundle",
		Use:   "upload <file> s3://<bucket>/<key>",
		Args:  cobra.ExactArgs(2),
		RunE:  doUpload,
	}
	rootCmd.AddCommand(Cmd)
}

func doUpload(cmd *cobra.Command, args []string) error {
	srcPath := args[0]
	destPath := args[1]

	if len(destPath) <= 5 || destPath[:5] != "s3://" {
		return errors.New("error: Invalid S3 path.")
	}

	data, err := ioutil.ReadFile(srcPath)
	if err != nil {
		return err
	}

	err = aws.S3Put(destPath, string(data))
	if err != nil {
		return err
	}

	return nil
}
