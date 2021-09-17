package aws

import (
	"context"
	"log"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/dathan/go-vault-dump/pkg/vault"
)

type ListS3 struct {
	Key  string
	Size int
}

func Upload(s3path string, body string) error {
	s3bucket := strings.Split(s3path[len("s3://"):], "/")[0]
	s3key := s3path[len("s3://"+s3bucket+"/"):]

	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return err
	}
	client := s3.NewFromConfig(cfg)
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

func List(s3path string, ext string) ([]ListS3, error) {

	s3bucket := strings.Split(s3path[len("s3://"):], "/")[0]
	s3prefix := vault.EnsureNoLeadingSlash(s3path[len("s3://"+s3bucket):])

	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatal(err)
	}
	client := s3.NewFromConfig(cfg)

	output, err := client.ListObjectsV2(context.TODO(), &s3.ListObjectsV2Input{
		Bucket: aws.String(s3bucket),
		Prefix: aws.String(s3prefix),
	})
	if err != nil {
		log.Fatal(err)
	}

	results := make([]ListS3, 0)
	for _, vv := range output.Contents {
		keyStr := aws.ToString(vv.Key)
		if keyStr[len(keyStr)-len(ext):] == ext {
			results = append(results, ListS3{Key: keyStr, Size: int(vv.Size)})
		}
	}

	return results, nil
}
