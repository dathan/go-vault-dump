package cmd

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/dathan/go-vault-dump/pkg/aws"
	"github.com/dathan/go-vault-dump/pkg/dump"
	"github.com/dathan/go-vault-dump/pkg/vault"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	cryptExt        = "aes"
	destFlag        = "dest"
	fileFlag        = "filename"
	ignoreKeysFlag  = "ignore-keys"
	ignorePathsFlag = "ignore-paths"
	kmsKeyFlag      = "kms-key"
	regionFlag      = "aws-region"
	vaFlag          = "vault-addr"
	vtFlag          = "vault-token"
)

var (
	cfgFile    string
	encoding   string
	kubeconfig string
	output     string
	tmpdir     string
	rootCmd    *cobra.Command

	// https://goreleaser.com/environment/#using-the-mainversion
	version = "dev"
	commit  = "none"
	date    = "unknown"
	builtBy = "unknown"
)

var (
	Verbose bool
)

func exitErr(e error) {
	log.SetOutput(os.Stderr)
	log.Println(e)
	os.Exit(1)
}

func init() {
	rootCmd = &cobra.Command{
		Use:   "vault-dump [flags] /vault/path[,...]",
		Short: "dump secrets from Vault",
		Args:  cobra.ExactArgs(1),
		RunE:  dumpVault,
	}

	logSetup()
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.vault-dump/config.yaml)")
	rootCmd.PersistentFlags().String(vaFlag, "https://127.0.0.1:8200", "vault url")
	rootCmd.PersistentFlags().String(vtFlag, "", "vault token")
	rootCmd.PersistentFlags().String(regionFlag, "us-east-1", "AWS region for KMS")
	rootCmd.PersistentFlags().StringSlice(ignoreKeysFlag, []string{}, "comma separated list of key names to ignore")
	rootCmd.PersistentFlags().StringSlice(ignorePathsFlag, []string{}, "comma separated list of paths to ignore")
	rootCmd.PersistentFlags().BoolVarP(&Verbose, "verbose", "v", false, "verbose output")
	rootCmd.Flags().StringP(fileFlag, "f", "vault-dump", "output filename (.json or .yaml extension will be added)")
	rootCmd.Flags().String(kmsKeyFlag, "", "KMS encryption key ARN (required for S3 uploads)")
	rootCmd.Flags().StringP(destFlag, "d", "", "output directory or S3 path")
	rootCmd.Flags().StringVarP(&encoding, "encoding", "e", "json", "encoding type [json, yaml]")
	rootCmd.Flags().StringVarP(&output, "output", "o", "file", "output type, [stdout, file, s3]")
	rootCmd.Flags().StringVarP(&kubeconfig, "kubeconfig", "k", "", "location of kube config file")
	rootCmd.Version = version

	viper.BindPFlag(ignorePathsFlag, rootCmd.PersistentFlags().Lookup(ignorePathsFlag))
	viper.BindPFlag(ignoreKeysFlag, rootCmd.PersistentFlags().Lookup(ignoreKeysFlag))
	viper.BindPFlag(regionFlag, rootCmd.PersistentFlags().Lookup(regionFlag))
	viper.BindPFlag(vaFlag, rootCmd.PersistentFlags().Lookup(vaFlag))
	viper.BindPFlag(vtFlag, rootCmd.PersistentFlags().Lookup(vtFlag))
	viper.BindPFlag(fileFlag, rootCmd.Flags().Lookup(fileFlag))
	viper.BindPFlag(destFlag, rootCmd.Flags().Lookup(destFlag))
	viper.BindPFlag(kmsKeyFlag, rootCmd.Flags().Lookup(kmsKeyFlag))
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
			return errors.New("Error: KMS key must be specified for S3 upload")
		}
		if outputPath == "" {
			return errors.New("Error: Must specify an output path for S3 upload")
		}
		s3path = vault.EnsureNoTrailingSlash(outputPath)
		if len(s3path) < 5 || s3path[:5] != "s3://" {
			return errors.New("Error: Output path for S3 upload must begin with s3://")
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
		plaintext, err := os.ReadFile(srcPath)
		if err != nil {
			// This is expected if no secrets were dumped
			log.Println("Nothing to upload")
			return nil
		}
		ciphertext, err := aws.KMSEncrypt(string(plaintext), kmsKey, viper.GetString(regionFlag))
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
