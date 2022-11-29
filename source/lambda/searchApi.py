from opensearchpy import OpenSearch, RequestsHttpConnection, AWSV4SignerAuth
import boto3
import requests
import json
import os

def lambda_handler(event, context):
  host = os.environ['OPENSEARCH_ENDPOINT']
  region = os.environ['REGION']
  index_name = os.environ['INDEX_NAME']
  searchText = event["queryStringParameters"]["q"]

  credentials = boto3.Session().get_credentials()
  auth = AWSV4SignerAuth(credentials, region)
  
  client = OpenSearch(
      hosts = [{'host': host, 'port': 443}],
      http_auth = auth,
      use_ssl = True,
      verify_certs = True,
      connection_class = RequestsHttpConnection
  )
  
  query = {
    "query": {
      "multi_match": {
        "query": searchText,
        "fields": ["name","textS3File", "mediaS3Key", "media", "text"]
      }
    }
  }
  searchResult = client.search(
    body = query,
    index = index_name
    )

  response = {
        'statusCode': 200,
        'headers': {
            'Access-Control-Allow-Headers': 'Content-Type',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
        },
        'body': json.dumps(searchResult)
    }

  return response
