from opensearchpy import OpenSearch, RequestsHttpConnection, AWSV4SignerAuth
import boto3
import datetime
import json
import os

def lambda_handler(event, context):

  mediaFileUri = event["TranscriptionJob"]["Media"]["MediaFileUri"]
  transcriptFileUri = event["TranscriptionJob"]["Transcript"]["TranscriptFileUri"]
  transcriptionJobName = event["TranscriptionJob"]["TranscriptionJobName"]
  s3BucketOutput = os.environ['S3_BUCKET_OUTPUT']

  s3Bucket = mediaFileUri.split("/")[2]
  # s3BucketOutput = "octank-doc-media-poc"
  s3TranscriptKey = transcriptFileUri.split("/")[4]+"/"+transcriptFileUri.split("/")[5]+"/"+transcriptFileUri.split("/")[6]
  s3MediaKey = mediaFileUri.split("/")[3]+"/"+mediaFileUri.split("/")[4]
  s3OutputMediaKey = "media/"+mediaFileUri.split("/")[4]

  s3 = boto3.client('s3')
  transcriptObj = s3.get_object(Bucket=s3BucketOutput, Key=s3TranscriptKey)
  transcriptRead = transcriptObj["Body"].read()
  transcriptReadDecode = json.loads(transcriptRead.decode("utf-8"))
  # print(transcriptReadDecode)
  transcriptText = transcriptReadDecode["results"]["transcripts"][0]["transcript"]
  # print(transcriptText)
  
  moveMediaS3(s3Bucket,s3MediaKey,s3BucketOutput,s3OutputMediaKey)
 
  indexMedia(s3OutputMediaKey, s3TranscriptKey, transcriptText)
  
def moveMediaS3 (bucketOrig, keyOrig, bucketDest, keyDest):
  s3 = boto3.resource('s3')
  copy_source = {
      'Bucket': bucketOrig,
      'Key': keyOrig
  }
  s3.meta.client.copy(copy_source, bucketDest, keyDest)
  
def indexMedia(mediaFileUri, transcriptFileUri, transcriptText):
  host = os.environ['OPENSEARCH_ENDPOINT']
  region = os.environ['REGION']
  index_name = os.environ['INDEX_NAME']

  credentials = boto3.Session().get_credentials()
  auth = AWSV4SignerAuth(credentials, region)

  client = OpenSearch(
      hosts = [{'host': host, 'port': 443}],
      http_auth = auth,
      use_ssl = True,
      verify_certs = True,
      connection_class = RequestsHttpConnection
  )
  
  document = {
    'name': mediaFileUri,
    'textoS3File': transcriptFileUri,
    'mediaS3Key': mediaFileUri,
    'media': 'mp4',
    'datetime': datetime.datetime.now(),
    'texto': transcriptText,
  }
  indexDoc = client.index(
    index = index_name,
    body = document,
    refresh = True
)
  print('\nSearch results:')
  print(indexDoc)