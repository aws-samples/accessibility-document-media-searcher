import json
import os
import boto3
import time
from botocore.client import Config
from helper import AwsHelper

def lambda_handler(event, context):
    TextractJobId = event["TextractJob"]["JobId"]
    s3Bucket = event["detail"]["bucket"]["name"]
    s3Object = event["detail"]["object"]["key"]
    apiCall = "StartDocumentTextDetection"
    VoiceId = os.environ['VOICE_ID']
    s3BucketOutput =  os.environ['S3_BUCKET_OUTPUT']
    s3KeyOutput = "media/"+s3Object.split("/")[1]
    
    resultFormattedText = getJobResults(apiCall,TextractJobId)
    resultObjName = putTextToS3(resultFormattedText,s3BucketOutput,s3KeyOutput)
        
    pollyPath = "media/"+resultObjName
    
    pollyJob = startSpeechSynthesisTask(resultFormattedText,s3BucketOutput,pollyPath,VoiceId)
    
    inputPolly = {
        "pollyJobId": pollyJob["TaskId"],
        "s3Bucket": s3BucketOutput,
        "s3PollyKey": pollyJob["OutputUri"],
        "s3InputKey": s3Object,
        "s3TextractKey": "textract/"+resultObjName+".txt"
    }
    # print(pollyJobId)
    return inputPolly
    
def getJobResults(api, jobId):

    pages = []
    formattedText = ""
    formattedTextNext = ""

    client = AwsHelper().getClient('textract')
    response = client.get_document_text_detection(JobId=jobId)
    pages.append(response)
    print("Resultset page received: {}".format(len(pages)))
    nextToken = None
    if('NextToken' in response):
        nextToken = response['NextToken']
        # textTextract = response['Blocks'][4]['Text']
        BlocksList = response['Blocks']
        # print("Next token: {}".format(nextToken))
        for i in BlocksList:
                try:
                    if 'Text' in i:
                        # print('Text: ', i['Text'])
                        formattedText+=(i['Text']+" ")
                    else:
                        print("No Text")
                except: 
                    print("EXCEPTION")

    while(nextToken):
        try:
            if(api == "StartDocumentTextDetection"):
                response = client.get_document_text_detection(JobId=jobId, NextToken=nextToken)
            else:
                response = client.get_document_analysis(JobId=jobId, NextToken=nextToken)
            pages.append(response)
            BlocksListNext = response['Blocks']
            ## Skip First summary response
            for j in BlocksListNext:
                    try:
                        if 'Text' in i:
                            formattedTextNext+=(j['Text']+" ")
                        else:
                            print("No Text")
                    except: 
                        print("EXCEPTION")
            nextToken = None
            if('NextToken' in response):
                nextToken = response['NextToken']


        except Exception as e:
            if(e.__class__.__name__ == 'ProvisionedThroughputExceededException'):
                print("ProvisionedThroughputExceededException.")
                print("Waiting for few seconds...")
                time.sleep(5)
                print("Waking up...")

    resultText= formattedText+formattedTextNext  
    return resultText
    
def putTextToS3(resultFormattedText,s3Bucket,s3Object):
    
    rm_ext = s3Object.split(".")
    obj_path = rm_ext[0].split("/")
    obj_name = obj_path[-1]

    s3Key = "textract/"+obj_name+".txt"
    
    client = AwsHelper().getClient('s3')
    client.put_object(Body=resultFormattedText,Bucket=s3Bucket, Key=s3Key)
    
    return obj_name

def startSpeechSynthesisTask(speechText,s3BucketOutput,s3ObjectOutput,VoiceId):
    
    client = AwsHelper().getClient('polly')
    
    response = client.start_speech_synthesis_task(OutputFormat="mp3",Text=speechText,OutputS3BucketName=s3BucketOutput,OutputS3KeyPrefix=s3ObjectOutput,VoiceId=VoiceId)
    
    return response["SynthesisTask"]