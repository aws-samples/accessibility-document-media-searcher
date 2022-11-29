import boto3
from botocore.client import Config
import os
import csv
import io

class AwsHelper:
    def getClient(self, name, awsRegion=None):
        config = Config(
            retries=dict(
                max_attempts=30
            )
        )
        if(awsRegion):
            return boto3.client(name, region_name=awsRegion, config=config)
        else:
            return boto3.client(name, config=config)

    def getResource(self, name, awsRegion=None):
        config = Config(
            retries=dict(
                max_attempts=30
            )
        )

        if(awsRegion):
            return boto3.resource(name, region_name=awsRegion, config=config)
        else:
            return boto3.resource(name, config=config)