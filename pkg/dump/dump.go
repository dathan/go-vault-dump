package dump

// root command expects a Vault path provided with no flag
// we verify this path exists and that the current token has access to it
// the two scenarios present themselves in the same way, so it can exist but look
// like it does not if your token is not granted access to see it

import (
	"fmt"
	"os"
	"strings"
	"sync"

	vaultapi "github.com/hashicorp/vault/api"

	"github.com/dathan/go-vault-dump/pkg/vault"
	alsoyaml "github.com/ghodss/yaml"
	"gopkg.in/yaml.v2"
)

var Debug bool

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
		DebugMsg(fmt.Sprintf("Unexpected input %s. writeToFile only understands json and yaml", o))
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
	CheckErr(err, "error when marshalling interface into []byte")
	return string(j)
}

func toYaml(i interface{}) string {
	y, err := yaml.Marshal(i)
	CheckErr(err, "error when marshalling interface into []byte")
	return string(y)
}

func updatePathIfKVv2(c *vaultapi.Client, path string) string {
	mountPath, v2, err := vault.IsKVv2(path, c)
	CheckErr(err, "error determining KV engine version")
	if v2 {
		path = vault.AddPrefixToVKVPath(path, mountPath, "metadata")
		CheckErr(err, "")
	}
	return path
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
	DebugMsg(string(b) + " bytes written successfully\n")

	err = f.Close()
	CheckErr(err, "failed to close file!")

	fmt.Println("file written successfully to " + path)
	return true
}

func writeToFile(s *sync.Map, outputEncoding, inputPath, outputPath string) bool {
	m := syncToMap(s)

	fileName := fmt.Sprintf("%s/%s.%s", outputPath, inputPath, outputEncoding)

	switch outputEncoding {
	case "json":
		_ = writeFile(toJSON(m), fileName)
	case "yaml":
		_ = writeFile(toYaml(m), fileName)
	default:
		DebugMsg(fmt.Sprintf("Unexpected input %s. writeToFile only understands json and yaml", outputEncoding))
		return false
	}
	return true
}

// CheckErr is a helper function that panics if the
// error is not passed and prints the msg string before
func CheckErr(e error, msg string) {
	if e != nil {
		if msg != "" {
			fmt.Println(msg)
		}
		panic(e)
	}
}

// DebugMsg is a helper function that prints the message
// if the debug flag is set
func DebugMsg(msg string) {
	if Debug {
		fmt.Println(msg)
	}
}

// FindVaultSecrets
func FindVaultSecrets(c *vaultapi.Client, path string, smPointer *sync.Map, wgPointer *sync.WaitGroup) {
	wgPointer.Add(1)
	DebugMsg(path)

	go func(wg *sync.WaitGroup, path string) {
		secret, err := c.Logical().List(path)
		CheckErr(err, "error listing path")

		if secret == nil || secret.Data == nil {
			panic(fmt.Sprintf("No value found at %s", path))
		}

		if _, ok := vault.ExtractListData(secret); !ok {
			panic(fmt.Sprintf("No entries found at %s", path))
		}

		for _, p := range secret.Data {
			for _, k := range p.([]interface{}) {
				newPath := path + "/" + k.(string)
				if isDir(k.(string)) { // type assertion
					FindVaultSecrets(c, vault.EnsureNoTrailingSlash(newPath), smPointer, wg)
				} else {
					// reconciling v2 secret engine requirement for list operation
					keyPath := strings.Replace(newPath, "metadata", "data", 1)
					DebugMsg(fmt.Sprintf("processing a secret at %s", keyPath))

					sec, err := c.Logical().Read(keyPath)
					CheckErr(err, "")

					if sec != nil {
						smPointer.Store(keyPath, sec.Data)
					}

				}
			}
		}
		wg.Done()
	}(wgPointer, path)
}

// GetPathForOutput
func GetPathForOutput(path string) string {
	if path == "" {
		path = "/tmp"
	}
	return vault.EnsureNoTrailingSlash(path)
}

// GetPathFromInput
func GetPathFromInput(c *vaultapi.Client, input string) string {
	if input == "" {
		panic("missing input path from command line")
	}
	u := updatePathIfKVv2(c, vault.SanitizePath(input))

	return vault.EnsureNoTrailingSlash(u)
}

// ProcessOutput takes action based on inputs to complete the
// desired output result
func ProcessOutput(s *sync.Map, et, ot, in, out string) {
	oe, _ := getOutputEncoding(et)
	switch ot {
	case "file":
		writeToFile(s, oe, in, out)
	case "stdout":
		printToStdOut(s, oe)
	default:
		panic(fmt.Sprintf("Unexpected output type %s. ", ot))
	}
}
