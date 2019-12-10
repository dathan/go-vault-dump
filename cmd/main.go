package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"

	vault_api "github.com/hashicorp/vault/api"
)

/**
 * Auth with VAULT using common environment flags
 * List all the keys
 * recursivly print out the values for each key
 */
var CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
var Logical *vault_api.Logical
var wg sync.WaitGroup
var sm sync.Map

func main() {

	config := vault_api.DefaultConfig()
	client, err := vault_api.NewClient(config)
	flag.Usage = usage()

	flag.Parse()

	if err != nil {
		flag.Usage()
	}

	if len(os.Args) <= 1 {
		flag.Usage()
	}

	init_path := os.Args[1]

	Logical = client.Logical()

	deepDive(init_path)
	wg.Wait()
	//spew.Dump(sm)
	sm.Range(func(key, val interface{}) bool {
		for k, v := range val.(map[string]interface{}) {
			fmt.Printf("%s ] %s : %s \n", key, k, v)
		}
		return true
	})
	panic("OH")
	dat, err := Logical.List(init_path)

	if err != nil {
		panic(err)
		flag.Usage()
	}

	if dat == nil {
		sec, _ := Logical.Read(init_path)
		for k, v := range sec.Data {
			fmt.Printf("%s : %s\n", k, v)
		}
	}

}

func deepDive(path string) {
	wg.Add(1)
	go func(wg *sync.WaitGroup, path string) {

		//fmt.Printf("Doing path: %s\n", path)

		path_additions, err := Logical.List(path)
		if err != nil {
			panic(err)
		}

		if path_additions != nil {
			for _, p := range path_additions.Data {
				for _, k := range p.([]interface{}) {
					//spew.Dump(k)
					pathcheck := k.(string)
					//fmt.Printf("PATHCHECK: %s\n", pathcheck)
					lastfield := string(pathcheck[len(pathcheck)-1])
					if strings.Compare(lastfield, "/") == 0 {
						new_path := strings.Trim(path, "/") + "/" + k.(string)
						deepDive(new_path)
					} else {

						sec, err := Logical.Read(path + k.(string))

						if err != nil {
							panic(err)
						}

						if sec != nil {
							sm.Store(path, sec.Data)
							//for k, v := range sec.Data {
							//fmt.Printf("path %s] %s : %s\n", path, k, v)
							//}
						}

					}
				}
			}
		}
		//fmt.Printf("DONE %s\n", path)
		wg.Done()
		return

	}(&wg, path)

}

func usage() func() {

	usage_str := `
	SECRET_NAME=$(kubectl -n $K8S_NAMESPACE get serviceaccount default -o jsonpath='{.secrets[0].name}')
	kubectl get secret $SECRET_NAME -o jsonpath='{.data.token}' -n $K8S_NAMESPACE | base64 --decode > /tmp/k8s-token
	export VAULT_TOKEN=` + "`vault write auth/$K8S_CLUSTER/login role=$K8S_NAMESPACE-role jwt=@/tmp/k8s-token | sed -n '3 p' | awk '{print $2}'`" + `
	echo -n $VAULT_TOKEN > /tmp/vault-token
	vault login token=$VAULT_TOKEN
	kubectl config set-context $CCONTEXT --namespace=$K8S_NAMESPACE
	./%s [start key path]
	`
	return func() {

		fmt.Fprintf(CommandLine.Output(), usage_str, os.Args[0])
		flag.PrintDefaults()
		os.Exit(2)
	}
}
