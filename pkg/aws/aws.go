package aws

import (
	"context"
	"log"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

const (
	DefaultAWSRegion string = "us-east-1"
)

var (
	AWSRegion   string
	AWSEndpoint string
	AWSConfig   aws.Config
)

func init() {
	var err error

	AWSRegion = os.Getenv("AWS_REGION")

	AWSEndpoint = os.Getenv("AWS_ENDPOINT")

	resolver := aws.EndpointResolverFunc(func(service, region string) (aws.Endpoint, error) {
		if AWSEndpoint != "" {
			return aws.Endpoint{
				PartitionID:   "aws",
				URL:           AWSEndpoint,
				SigningRegion: AWSRegion,
			}, nil
		}
		return aws.Endpoint{}, &aws.EndpointNotFoundError{}
	})
	AWSConfig, err = config.LoadDefaultConfig(
		context.TODO(),
		config.WithRegion(AWSRegion),
		config.WithEndpointResolver(resolver),
	)
	if err != nil {
		log.Fatalf("Error initializing AWS client: %s", err)
	}

}

func NewKMSClient() *kms.Client {
	return kms.NewFromConfig(AWSConfig)
}

func NewS3Client() *s3.Client {
	return s3.NewFromConfig(AWSConfig, func(o *s3.Options) {
		o.UsePathStyle = true
	})

}
