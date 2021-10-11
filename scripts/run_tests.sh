export AWS_ENDPOINT=http://localhost:4566
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export VAULT_ADDR=http://localhost:8200
export VAULT_TOKEN=Test_123
export KMS_KEY_ARN=$(docker-compose exec localstack aws --endpoint-url=http://localhost:4566 --region=us-east-1 kms create-key | jq .KeyMetadata.Arn -rj)
docker-compose exec localstack aws --endpoint-url=http://localhost:4566 s3 rm s3://test --recursive
docker-compose exec localstack aws --endpoint-url=http://localhost:4566 s3 mb s3://test
docker-compose exec vault vault kv put /secret/foo/bar baz=bat
go test ./pkg/aws ./pkg/print ./pkg/vault -coverprofile=coverage.out
