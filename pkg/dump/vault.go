package dump

import (
	"context"
	"log"
	"strings"
	"sync"

	"github.com/dathan/go-vault-dump/pkg/vault"
	vaultapi "github.com/hashicorp/vault/api"
)

type secret struct {
	path string
	data interface{}
}
type SecretScraper struct {
	context      context.Context
	errorChan    chan error
	leafStream   chan string
	secretStream chan secret
	vault        *vaultapi.Client
	waitgroup    *sync.WaitGroup
	Data         map[string]interface{}
}

func (s *SecretScraper) New(vault *vaultapi.Client) SecretScraper {
	return SecretScraper{
		context:      context.TODO(),
		errorChan:    make(chan error, 1),
		leafStream:   make(chan string, 1000),
		secretStream: make(chan secret, 1000),
		waitgroup:    new(sync.WaitGroup),
		vault:        vault,
		Data:         make(map[string]interface{}),
	}
}

// Start creates n number of workers
func (s *SecretScraper) Start(n int, path string) {

	s.climber(path)
	close(s.leafStream)

	// ctx, done := context.WithCancel(context.TODO())
	s.waitgroup.Add(n)
	for i := 0; i != n; i++ {
		go s.getSecretFromLeafStream(context.TODO(), i)
	}
	s.waitgroup.Wait()

	// once the secretStream is closed
	close(s.secretStream)
	// convert the stream into a map
	for secret := range s.secretStream {
		s.Data[secret.path] = secret.data
	}

	// done()

}

// climber finds leaves to put on the leafStream
func (s *SecretScraper) climber(path string) {
	results, err := s.vault.Logical().List(path)
	if err != nil {
		select {
		case s.errorChan <- err:
			log.Printf("failed to list on path %s, %s\n", path, err.Error())
		default:
			log.Println("another error occurred, " + err.Error())
		}
	}

	if data, ok := vault.ExtractListData(results); !ok {
		select {
		case s.errorChan <- err:
			log.Printf("No entries found at %s\n", path) // if a path is a leaf, this will occur
		default:
			log.Println("another error occurred")
		}
	} else {
		for _, v := range data {
			newPath := vault.EnsureNoTrailingSlash(path + "/" + v.(string))
			if isDir(v.(string)) {
				s.climber(newPath)
			} else {
				// log.Printf("found leaf: %v", newPath)
				s.leafStream <- newPath
			}
		}
	}
}

//getSecretFromLeafStream takes leafs off its stream and converts them into secrets
// and adds those to another stream until an error occurs or the context is shutdown
func (s *SecretScraper) getSecretFromLeafStream(ctx context.Context, id int) {
	defer s.waitgroup.Done()

	leaf := <-s.leafStream
	// reconciling v2 secret engine requirement for list operation
	path := strings.Replace(leaf, "metadata", "data", 1)

	vaultSecret, err := s.vault.Logical().Read(path)
	if err != nil {
		log.Printf("failed to get secrets in %s, %s\n", path, err.Error())
	}

	secret := secret{
		path: path,
		data: vaultSecret.Data["data"],
	}
	s.secretStream <- secret
}

func (s *SecretScraper) ProcessOutput(c *Config) {
	switch c.outputType {
	case "file":
		c.writeToFile(s.Data)
	case "stdout":
		c.printToStdOut(s.Data)
	default:
		log.Panicf("Unexpected output type %s\n", c.outputType)
	}
}
