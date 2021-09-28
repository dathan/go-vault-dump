docker-compose down
docker-compose up -d vault localstack
echo waiting...
sleep 10
docker-compose exec vault vault secrets disable secret
docker-compose exec vault vault secrets enable -version=1 -path=/secret kv
docker-compose exec vault vault secrets enable database
docker-compose exec vault vault kv put /secret/foo/bar baz=bat
docker-compose exec localstack aws --endpoint-url=http://localhost:4566 s3 mb s3://test
echo done
