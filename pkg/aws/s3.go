package aws

import (
	"context"
	"io/ioutil"
	"log"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/dathan/go-vault-dump/pkg/vault"
)

type S3ListResult struct {
	Key  string
	Size int
}

func s3client() (*s3.Client, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return nil, err
	}
	client := s3.NewFromConfig(cfg)
	return client, nil
}

func S3Put(s3path string, body string) error {
	s3bucket := strings.Split(s3path[len("s3://"):], "/")[0]
	s3key := s3path[len("s3://"+s3bucket+"/"):]

	client, err := s3client()
	if err != nil {
		return err
	}
	params := &s3.PutObjectInput{
		Bucket: &s3bucket,
		Key:    &s3key,
		Body:   strings.NewReader(body),
	}

	_, err = client.PutObject(context.TODO(), params)
	if err != nil {
		return err
	}
	log.Printf("File uploaded to %s", s3path)
	return nil
}

func S3List(s3path string, ext string) ([]S3ListResult, error) {

	s3bucket := strings.Split(s3path[len("s3://"):], "/")[0]
	s3prefix := vault.EnsureNoLeadingSlash(s3path[len("s3://"+s3bucket):])

	client, err := s3client()
	if err != nil {
		return nil, err
	}

	output, err := client.ListObjectsV2(context.TODO(), &s3.ListObjectsV2Input{
		Bucket: aws.String(s3bucket),
		Prefix: aws.String(s3prefix),
	})
	if err != nil {
		log.Fatal(err)
	}

	results := make([]S3ListResult, 0)
	for _, vv := range output.Contents {
		keyStr := aws.ToString(vv.Key)
		if keyStr[len(keyStr)-len(ext):] == ext {
			results = append(results, S3ListResult{Key: keyStr, Size: int(vv.Size)})
		}
	}

	return results, nil
}

func S3Get(s3path string) ([]byte, error) {
	s3bucket := strings.Split(s3path[len("s3://"):], "/")[0]
	s3key := vault.EnsureNoLeadingSlash(s3path[len("s3://"+s3bucket):])

	client, err := s3client()
	if err != nil {
		return []byte(""), err
	}
	result, err := client.GetObject(context.TODO(), &s3.GetObjectInput{
		Bucket: &s3bucket,
		Key:    &s3key,
	})
	if err != nil {
		return []byte(""), err
	}

	data, err := ioutil.ReadAll(result.Body)
	if err != nil {
		return []byte(""), err
	}

	return data, nil
}
