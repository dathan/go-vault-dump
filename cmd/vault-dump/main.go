package main

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/dathan/go-vault-dump/pkg/vault"
	vaultapi "github.com/hashicorp/vault/api"
	"gopkg.in/yaml.v2"

	alsoyaml "github.com/ghodss/yaml"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const debugFlag = "debug"
const vaFlag = "vault-addr"
const vtFlag = "vault-token"

/**
 * Auth with VAULT using common environment flags
 * List all the keys
 * recursively print out the values for each key
 */

var (
	debug bool
	wg    sync.WaitGroup
)

func init() {
	pflag.String(vaFlag, "https://127.0.0.1:8200", "vault url")
	pflag.String(vtFlag, "", "vault token")
	pflag.String("enc", "yaml", "encoding type [json, yaml]")
	pflag.String("o", "stdout", "output type, [stdout, file]")
	pflag.Bool("debug", false, "enables verbose messages")
	pflag.CommandLine.ParseErrorsWhitelist.UnknownFlags = true
	pflag.Parse()
	viper.BindPFlags(pflag.CommandLine)
	viper.AutomaticEnv()

}

func checkErr(e error, msg string) {
	if e != nil {
		if msg != "" {
			fmt.Println(msg)
		}
		panic(e)
	}
}

func debugMsg(msg string) {
	if debug {
		fmt.Println(msg)
	}
}

func findVaultSecrets(c *vaultapi.Client, path string, smPointer *sync.Map) {
	wg.Add(1)
	debugMsg(path)

	go func(wg *sync.WaitGroup, path string) {
		secret, err := c.Logical().List(path)
		checkErr(err, "error listing path")

		if secret == nil || secret.Data == nil {
			panic(fmt.Sprintf("No value found at %s", path))
		}

		// If the secret is wrapped, return the wrapped response.
		if secret.WrapInfo != nil && secret.WrapInfo.TTL != 0 {
			// _ = vaultcommand.OutputSecret(vaultcommand.KVListCommand.UI, secret)
			fmt.Println("secret wrapped")
		}

		if _, ok := vault.ExtractListData(secret); !ok {
			panic(fmt.Sprintf("No entries found at %s", path))
		}

		for _, p := range secret.Data {
			for _, k := range p.([]interface{}) {
				newPath := path + "/" + k.(string)
				if isDir(k.(string)) { // type assertion
					findVaultSecrets(c, vault.EnsureNoTrailingSlash(newPath), smPointer)
				} else {
					// reconciling v2 secret engine requirement for list operation
					keyPath := strings.Replace(newPath, "metadata", "data", 1)
					debugMsg(fmt.Sprintf("processing a secret at %s", keyPath))

					sec, err := c.Logical().Read(keyPath)
					checkErr(err, "")

					if sec != nil {
						smPointer.Store(keyPath, sec.Data)
					}

				}
			}
		}
		wg.Done()
	}(&wg, path)
}

func getPathFromInput(input string) string {
	if input == "" {
		panic("missing input path from command line")
	}
	return vault.EnsureNoTrailingSlash(vault.SanitizePath(input))
}

func isDir(p string) bool {
	lastChar := p[len(p)-1:]
	if lastChar != "/" {
		return false
	}
	return true
}

func printToStdOut(s *sync.Map, o string) bool {
	m := syncToMap(s)
	switch o {
	case "json":
		fmt.Println(toJSON(m))
	case "yaml":
		fmt.Println(toYaml(m))
	default:
		debugMsg(fmt.Sprintf("Unexpected input %s. writeToFile only understands json and yaml", o))
		return false
	}
	return true
}

func syncToMap(s *sync.Map) map[interface{}]interface{} {
	m := make(map[interface{}]interface{})
	s.Range(func(key, val interface{}) bool {
		m[key] = val
		return true
	})
	return m
}

func toJSON(i interface{}) string {
	y, err := yaml.Marshal(i)
	j, err := alsoyaml.YAMLToJSON(y)
	checkErr(err, "error when marshalling interface into []byte")
	return string(j)
}

func toYaml(i interface{}) string {
	y, err := yaml.Marshal(i)
	checkErr(err, "error when marshalling interface into []byte")
	return string(y)
}

func updatePathIfKVv2(c *vaultapi.Client, path string) string {
	mountPath, v2, err := vault.IsKVv2(path, c)
	checkErr(err, "error determining KV engine version")
	if v2 {
		path = vault.AddPrefixToVKVPath(path, mountPath, "metadata")
		checkErr(err, "")
	}
	return path
}

func getPathForOutput(path string) string {
	if path == "" {
		path = "/tmp"
	}
	return vault.EnsureNoTrailingSlash(path)
}

func writeToFile(s *sync.Map, outputEncoding string) bool {
	m := syncToMap(s)
	inputPath := getPathFromInput(pflag.Arg(0))
	outputPath := getPathForOutput(pflag.Arg(1))

	fileName := fmt.Sprintf("%s/%s.%s", outputPath, inputPath, outputEncoding)

	switch outputEncoding {
	case "json":
		_ = writeFile(toJSON(m), fileName)
	case "yaml":
		_ = writeFile(toYaml(m), fileName)
	default:
		debugMsg(fmt.Sprintf("Unexpected input %s. writeToFile only understands json and yaml", outputEncoding))
		return false
	}
	return true
}

func writeFile(data, path string) bool {
	f, err := os.Create(path)
	if err != nil {
		fmt.Println(err)
		f.Close()
		return false
	}

	b, err := f.WriteString(data)
	if err != nil {
		fmt.Println(err)
		return false
	}
	debugMsg(string(b) + " bytes written successfully\n")

	err = f.Close()
	checkErr(err, "failed to close file!")

	fmt.Println("file written successfully to " + path)
	return true
}

func main() {

	if viper.IsSet(debugFlag) {
		debug = true
	}
	config := vaultapi.DefaultConfig()
	client, err := vaultapi.NewClient(config)
	checkErr(err, "failed vault client init")

	if viper.IsSet(vaFlag) {
		debugMsg("flag set: " + vaFlag)
		client.SetAddress(viper.GetString(vaFlag))
	}

	if viper.IsSet(vtFlag) {
		debugMsg("flag set: " + vtFlag)
		client.SetToken(viper.GetString(vtFlag))
	}

	inputPath := getPathFromInput(pflag.Arg(0))
	inputPath = updatePathIfKVv2(client, inputPath)

	var sm sync.Map
	findVaultSecrets(client, inputPath, &sm)
	wg.Wait()

	outputEncoding, _ := getOutputEncoding(viper.GetString("enc"))
	processOutput(&sm, outputEncoding, viper.GetString("o"))

}

func getOutputEncoding(encodingType string) (string, bool) {
	switch encodingType {
	case "yaml":
		return "yaml", false
	case "json":
		return "json", false
	default:
		panic(fmt.Sprintf("Unexpected encoding type %s. ", encodingType))
	}
}

func processOutput(s *sync.Map, et string, ot string) {
	switch ot {
	case "file":
		writeToFile(s, et)
	case "stdout":
		printToStdOut(s, et)
	default:
		panic(fmt.Sprintf("Unexpected output type %s. ", ot))
	}
}
