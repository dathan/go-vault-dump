package dump

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/spf13/viper"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	tokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token"
)

// ToKube
func ToKube(c *Config, s *sync.Map) {
	var config *rest.Config
	var err error

	if _, err := os.Stat(tokenFile); err == nil {
		fmt.Println("Using in cluster config")
		config, err = rest.InClusterConfig()
		if err != nil {
			panic(err.Error())
		}
	} else {
		fmt.Println("Using out of cluster config")
		config, err = clientcmd.BuildConfigFromFlags("", viper.GetString("kc"))
	}
	CheckErr(err, "failed to setup kube config")

	kClient, err := kubernetes.NewForConfig(config)
	CheckErr(err, "failed to setup kube client")

	secrets, _ := kClient.CoreV1().Secrets("").List(context.TODO(), metav1.ListOptions{})

	fmt.Printf("There are %d secrets in the cluster\n", len(secrets.Items))

	m := make(map[interface{}]interface{})
	s.Range(func(key, val interface{}) bool {
		m[key] = val
		return true
	})
	fmt.Printf("There are %d secrets in the mountpath\n", len(m))
	for k, v := range m {

		createOrModifySecret(kClient, k.(string), v.(map[string]interface{})) // type assertion syntax
	}
}

func createOrModifySecret(client *kubernetes.Clientset, key string, value map[string]interface{}) {
	fmt.Println(key)
	fmt.Println(value["data"])
	secretMap := make(map[string]string)
	for k, v := range value["data"].(map[string]interface{}) {
		// convert to map[string]string
		secretMap[k] = v.(string)
	}
	// fmt.Println(secretMap)
	// for i, j := range secretMap {
	// 	fmt.Println(fmt.Sprintf("key: %s, value: %s", i, j))
	// }

	secretName := strings.Join(strings.Split(key, "/")[1:], ".")
	kSecret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: secretName,
		},
		StringData: secretMap,
	}
	secretExists, err := client.CoreV1().Secrets("default").Get(context.TODO(), secretName, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		fmt.Println("DOESNT EXIST")
		_, err := client.CoreV1().Secrets("default").Create(context.TODO(), &kSecret, metav1.CreateOptions{})
		CheckErr(err, "failed to create new secret")
	} else if err != nil {
		CheckErr(err, "failed to get secret with name "+secretName)
	}

	for k1, v1 := range secretExists.Data {
		fmt.Println(fmt.Sprintf("key: %s, value: %s", k1, string(v1)))
	}

}
