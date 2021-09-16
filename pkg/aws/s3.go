package aws

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

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
		Key: &s3key,
		Body: strings.NewReader(body),
	}
	_, err = client.PutObject(context.TODO(), params)
	if err != nil {
		return err
	}
	return nil
}