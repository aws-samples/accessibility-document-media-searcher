from opensearchpy import OpenSearch, RequestsHttpConnection, AWSV4SignerAuth
import boto3
import datetime
import os

def lambda_handler(event, context):

  pollyJobId = event["pollyJobId"]
  s3Bucket = event["s3Bucket"]
  s3InputKey = event["s3InputKey"]
  s3TextractKey = event["s3TextractKey"]
  s3PollyKey = event["s3PollyKey"]

  s3 = boto3.client('s3')
  textractObj = s3.get_object(Bucket=s3Bucket, Key=s3TextractKey)
  textractText = textractObj["Body"].read()
  textractTextDecode = textractText.decode("utf-8")
  s3BucketPath = "s3://"+s3Bucket+"/"
  docS3Key = s3BucketPath+s3InputKey
  texractS3Key = s3BucketPath+s3TextractKey
  
  indexData(docS3Key, texractS3Key, s3PollyKey, textractTextDecode, pollyJobId)
  
def indexData(docS3Key, texractS3Key, s3PollyKey, textractTextDecode, pollyJobId):
  host = os.environ['OPENSEARCH_ENDPOINT']
  region = os.environ['REGION']
  index_name = os.environ['INDEX_NAME']
  credentials = boto3.Session().get_credentials()
  auth = AWSV4SignerAuth(credentials, region)
  mediaS3Key = s3PollyKey.split("/")[-2]+"/"+s3PollyKey.split("/")[-1]
  textS3File = texractS3Key.split("/")[-2]+"/"+texractS3Key.split("/")[-1]
  
  client = OpenSearch(
      hosts = [{'host': host, 'port': 443}],
      http_auth = auth,
      use_ssl = True,
      verify_certs = True,
      connection_class = RequestsHttpConnection
  )
  
  document = {
    'name': docS3Key,
    'textS3File': textS3File,
    'mediaS3Key': mediaS3Key,
    'media': 'mp3',
    'datetime': datetime.datetime.now(),
    'text': textractTextDecode,
  }

  indexDoc = client.index(
    index = index_name,
    body = document,
    refresh = True,
    id  = pollyJobId
)
  print('\nSearch results:')
  print(indexDoc)