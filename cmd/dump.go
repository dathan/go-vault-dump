package cmd

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/dathan/go-vault-dump/pkg/aws"
	"github.com/dathan/go-vault-dump/pkg/dump"
	"github.com/dathan/go-vault-dump/pkg/vault"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	cryptExt   = "aes"
	destFlag   = "dest"
	fileFlag   = "filename"
	kmsKeyFlag = "kms-key"
)

var (
	encoding   string
	kubeconfig string
	output     string
	dumpCmd    *cobra.Command
)

func init() {
	dumpCmd = &cobra.Command{
		Use:   "dump [flags] /vault/path[,...]",
		Short: "Dump secrets from Vault",
		Args:  cobra.ExactArgs(1),
		RunE:  dumpVault,
	}

	dumpCmd.Flags().StringP(fileFlag, "f", "vault-dump", "output filename (.json or .yaml extension will be added)")
	dumpCmd.Flags().String(kmsKeyFlag, "", "KMS encryption key ARN (required for S3 uploads)")
	dumpCmd.Flags().StringP(destFlag, "d", "", "output directory or S3 path")
	dumpCmd.Flags().StringVarP(&encoding, "encoding", "e", "json", "encoding type [json, yaml]")
	dumpCmd.Flags().StringVarP(&output, "output", "o", "file", "output type, [stdout, file, s3]")
	dumpCmd.Flags().StringVarP(&kubeconfig, "kubeconfig", "k", "", "location of kube config file")

	viper.BindPFlag(fileFlag, dumpCmd.Flags().Lookup(fileFlag))
	viper.BindPFlag(destFlag, dumpCmd.Flags().Lookup(destFlag))
	viper.BindPFlag(kmsKeyFlag, dumpCmd.Flags().Lookup(kmsKeyFlag))

	rootCmd.AddCommand(dumpCmd)
}

func dumpVault(cmd *cobra.Command, args []string) error {

	paths := args[0]

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

	outputPath := viper.GetString(destFlag)
	if len(outputPath) > 5 && outputPath[:5] == "s3://" {
		output = "s3"
	}

	s3path := ""
	kmsKey := viper.GetString(kmsKeyFlag)
	if output == "s3" {
		if kmsKey == "" {
			return errors.New("error: KMS key must be specified for S3 upload")
		}
		if outputPath == "" {
			return errors.New("error: Must specify an output path for S3 upload")
		}
		s3path = vault.EnsureNoTrailingSlash(outputPath)
		if len(s3path) < 5 || s3path[:5] != "s3://" {
			return errors.New("error: Output path for S3 upload must begin with s3://")
		}
		outputPath, err = ioutil.TempDir("", "vault-dump-*")
		if err != nil {
			log.Fatal(err)
		}
	}
	defer func() {
		if output == "s3" {
			os.RemoveAll(outputPath)
		}
	}()
	outputPath = dump.GetPathForOutput(outputPath)

	outputConfig, err := dump.NewOutput(
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
		InputPath:   paths,
		Filename:    outputFilename,
		Output:      outputConfig,
		VaultConfig: vc,
	})
	if err != nil {
		return err
	}

	if err := dumper.Secrets(); err != nil {
		return err
	}

	if output == "s3" {
		srcPath := fmt.Sprintf("%s/%s.%s", outputPath, outputFilename, encoding)
		dstPath := fmt.Sprintf("%s/%s.%s.%s", s3path, outputFilename, encoding, cryptExt)
		plaintext, err := ioutil.ReadFile(srcPath)
		if err != nil {
			// This is expected if no secrets were dumped
			log.Println("Nothing to upload")
			return nil
		}
		ciphertext, err := aws.KMSEncrypt(string(plaintext), kmsKey)
		if err != nil {
			return err
		}
		err = aws.S3Put(dstPath, ciphertext)
		if err != nil {
			return err
		}
	}

	return nil
}
