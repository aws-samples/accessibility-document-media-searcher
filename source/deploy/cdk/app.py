#!/usr/bin/env python3
# from constructs import Construct
from aws_cdk import App, CfnOutput
from stack.adms_stack import JobPollerStack

app = App()
JobPollerStack(app, "adms")
app.synth()