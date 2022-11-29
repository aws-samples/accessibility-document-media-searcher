import os
import string
import secrets
from aws_cdk import (
    Duration as duration,
    CfnOutput as output,
    custom_resources as cr,
    aws_stepfunctions as _aws_stepfunctions,
    aws_stepfunctions_tasks as _aws_stepfunctions_tasks,
    aws_lambda as _lambda,
    aws_apigateway as apigateway,
    aws_cognito as cognito,
    aws_s3 as s3,
    aws_s3_deployment as s3_deploy,
    aws_s3_assets as s3_assets,
    aws_ec2 as ec2,
    aws_opensearchservice as opensearch,
    aws_events as events,
    aws_events_targets as targets,
    aws_cloudfront as cloudfront,
    aws_cloudfront_origins as origins,
    aws_iam as iam,
    App, Duration, Stack
)

class JobPollerStack(Stack):
    def __init__(self, app: App, id: str, **kwargs) -> None:
        super().__init__(app, id, **kwargs)
        # region = "us-east-1"
        index_name = "adms-index"
        # voice_id = "Vitoria"
        os_instance_type="m6g.large.search"
        ebs_volume_size=100
        data_nodes=2        
        region = os.environ["REGION"]
        email = os.environ["EMAIL"]
        # index_name = os.environ["INDEX_NAME"]
        voice_id = os.environ["VOICE_ID"]
        # os_instance_type=os.environ["OS_INSTANCE_TYPE"]
        # ebs_volume_size=int(os.environ["EBS_VOLUME_SIZE"])
        # data_nodes=int(os.environ["DATA_NODES"])
        alphabet = string.ascii_letters
        password = ''.join(secrets.choice(alphabet) for i in range(10))  # for a 10-character password

        # S3 Buckets
        cors_rule = s3.CorsRule(
            allowed_methods=[s3.HttpMethods.GET, s3.HttpMethods.POST, s3.HttpMethods.HEAD, s3.HttpMethods.PUT, s3.HttpMethods.DELETE],
            allowed_origins=["*"],
            allowed_headers=["*"],
            exposed_headers=["ETag"]
        )
        bucket_front = s3.Bucket(self, "bucket-front",
            website_index_document="login.html",
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            object_ownership=s3.ObjectOwnership.BUCKET_OWNER_ENFORCED
        )
        bucket_raw = s3.Bucket(self, "bucket-raw", 
            cors=([cors_rule]),
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            event_bridge_enabled=True,
            object_ownership=s3.ObjectOwnership.BUCKET_OWNER_PREFERRED
            )
      
        
        # VPC
        vpc = ec2.Vpc(self, "adms-vpc")

        # VPC Subnets
        selection = vpc.select_subnets(
            subnet_type=ec2.SubnetType.PRIVATE_WITH_NAT
        )
        for subnet in selection.subnets:
            pass

        # Security Group
        security_group=ec2.SecurityGroup(self, "adms-sg",vpc=vpc)
        security_group.add_ingress_rule(security_group,ec2.Port.all_traffic(),"adms rule",False)
       
        iam.CfnServiceLinkedRole(self, "OpensearchSLR",
            aws_service_name="opensearchservice.amazonaws.com"
        )
        # Opensearch
        domain = opensearch.Domain(self, "ADMSDomain",
            version=opensearch.EngineVersion.OPENSEARCH_1_3,
            ebs=opensearch.EbsOptions(
                volume_size=ebs_volume_size,
                volume_type=ec2.EbsDeviceVolumeType.GP3
            ),
            capacity=opensearch.CapacityConfig(
                data_nodes=data_nodes,
                data_node_instance_type=os_instance_type
            ), 
            zone_awareness=opensearch.ZoneAwarenessConfig(
                availability_zone_count=data_nodes
            ),                       
            node_to_node_encryption=True,
            vpc=vpc,
            vpc_subnets=[ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS
            )],
            security_groups=[security_group],
            encryption_at_rest=opensearch.EncryptionAtRestOptions(
                enabled=True
            )
        )        

        # Lambda Functions
        format_textract = _lambda.Function(self, 'format_textract', 
                                        handler='formatTextract.lambda_handler',
                                        runtime=_lambda.Runtime.PYTHON_3_8,
                                        timeout= duration.seconds(300),
                                        code=_lambda.Code.from_asset('../../lambda',exclude=['searchApi.py','indexDoc.py','indexMedia.py']))
        format_textract.add_environment("S3_BUCKET_OUTPUT", bucket_front.bucket_name)
        format_textract.add_environment("VOICE_ID", voice_id)
        format_textract.add_environment("REGION", region)
        format_textract.add_environment("OPENSEARCH_ENDPOINT", domain.domain_endpoint)
        format_textract.add_environment("INDEX_NAME", index_name)

        index_doc = _lambda.Function(self, 'index_doc', 
                                        handler='indexDoc.lambda_handler',
                                        runtime=_lambda.Runtime.PYTHON_3_8,
                                        timeout= duration.seconds(300),
                                        vpc=vpc,
                                        vpc_subnets=ec2.SubnetSelection(
                                            subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS
                                        ),
                                        security_groups=([security_group]),
                                        code=_lambda.Code.from_asset('../../lambda',exclude=['searchApi.py','formatTextract.py','indexMedia.py']))
        index_doc.add_environment("S3_BUCKET_OUTPUT", bucket_front.bucket_name)
        index_doc.add_environment("VOICE_ID", voice_id)
        index_doc.add_environment("REGION", region)
        index_doc.add_environment("OPENSEARCH_ENDPOINT", domain.domain_endpoint)
        index_doc.add_environment("INDEX_NAME", index_name)        
        index_media = _lambda.Function(self, 'index_media', 
                                        handler='indexMedia.lambda_handler',
                                        runtime=_lambda.Runtime.PYTHON_3_8,
                                        timeout= duration.seconds(300),
                                        vpc=vpc,
                                        vpc_subnets=ec2.SubnetSelection(
                                            subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS
                                        ),
                                        security_groups=([security_group]),
                                        code=_lambda.Code.from_asset('../../lambda',exclude=['searchApi.py','formatTextract.py','indexDoc.py']))
        index_media.add_environment("S3_BUCKET_OUTPUT", bucket_front.bucket_name)
        index_media.add_environment("VOICE_ID", voice_id)
        index_media.add_environment("REGION", region)
        index_media.add_environment("OPENSEARCH_ENDPOINT", domain.domain_endpoint)
        index_media.add_environment("INDEX_NAME", index_name)
        search_api = _lambda.Function(self, 'search_api', 
                                        handler='searchApi.lambda_handler',
                                        runtime=_lambda.Runtime.PYTHON_3_8,
                                        timeout= duration.seconds(300),
                                        vpc=vpc,
                                        vpc_subnets=ec2.SubnetSelection(
                                            subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS
                                        ),
                                        security_groups=([security_group]),
                                        code=_lambda.Code.from_asset('../../lambda',exclude=['formatTextract.py','indexDoc.py','indexMedia.py']))
        search_api.add_environment("S3_BUCKET_OUTPUT", bucket_front.bucket_name)
        search_api.add_environment("VOICE_ID", voice_id)
        search_api.add_environment("REGION", region)
        search_api.add_environment("OPENSEARCH_ENDPOINT", domain.domain_endpoint)
        search_api.add_environment("INDEX_NAME", index_name)

        # Cloud Front
        origin_access_identity = cloudfront.OriginAccessIdentity(self, "ADMSOriginAccessIdentity",
            comment="ADMS"
        )
      
        adms_dist = cloudfront.CloudFrontWebDistribution(self, "admsWebDistribution",
            origin_configs=[cloudfront.SourceConfiguration(
                s3_origin_source=cloudfront.S3OriginConfig(
                    s3_bucket_source=bucket_front,
                    origin_access_identity=origin_access_identity
                ),
                behaviors=[cloudfront.Behavior(is_default_behavior=True)]
            )
            ]
        )
  
        output(self, "WebSiteDistributionOut", value="https://"+adms_dist.distribution_domain_name+"/login.html")

       # Cognito UserPool
        pool = cognito.UserPool(self, "Pool",
            auto_verify=cognito.AutoVerifiedAttrs(email=True),          
            user_invitation=cognito.UserInvitationConfig(
                email_subject="Invite to join ADMS!",
                # email_body="You are invited to try the Accessibility Document Media Searcher. Your credentials are: Username: {username} Password: " + password +"Please wait until the deployent has completed before accessing the website. Please sign in with the user name and your password provided above at: https://{adms_dist.distribution_domain_name}/login.html   ID:{####}",
                email_body="<p>You are invited to try the Accessibility Document Media Searcher. Your credentials are:</p> \
                <p> \
                Username: <strong>{username}</strong><br /> \
                Password: <strong>"+password+"</strong> \
                </p> \
                <p>\
                Please wait until the deployent has completed for ADMS stack before accessing the website \
                </p>\
                <p> \
                Please sign in with the user name and your password provided above at: <br /> \
                https://"+ adms_dist.distribution_domain_name+ "/login.html \
                </p><br /><br />RequestID: {####}\
                ",
            ),
            password_policy=cognito.PasswordPolicy(
                min_length=6,
                temp_password_validity=Duration.days(7)
            )
        )
        poolClient = pool.add_client("app-client",
            o_auth=cognito.OAuthSettings(
                flows=cognito.OAuthFlows(
                    authorization_code_grant=True,
                    implicit_code_grant=True
                ),
                scopes=[cognito.OAuthScope.OPENID,cognito.OAuthScope.EMAIL,cognito.OAuthScope.COGNITO_ADMIN],
                callback_urls=["https://"+adms_dist.distribution_domain_name+"/index.html"],
                logout_urls=["https://"+adms_dist.distribution_domain_name+"/login.html"]
            )
        )  

        # Cognito Identity Pool      
        admsIdentityPool = cognito.CfnIdentityPool(self, "ADMSIdentityPool",
            cognito_identity_providers=pool.identity_providers,
            allow_unauthenticated_identities=True
        )
        # Cognito Identity Pool Role
        identitypoolAuthAssumeRolePolicyDoc = iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            actions=[
                                "mobileanalytics:PutEvents",
                                "cognito-sync:*",
                                "cognito-identity:*"
                            ],
                            resources= [
                                "*"
                            ]
                        ),
                        iam.PolicyStatement(
                            actions=[
                                "S3:*"
                            ],
                            resources= [
                                "arn:aws:s3:::"+bucket_front.bucket_name+"/*",
                                "arn:aws:s3:::"+bucket_raw.bucket_name+"/*",
                                "arn:aws:s3:::"+bucket_front.bucket_name,
                                "arn:aws:s3:::"+bucket_raw.bucket_name

                            ]
                        )
                    ]
        )
        identitypoolAuthRole = iam.Role(self, "IdentityPoolAuthRole",
            assumed_by=iam.FederatedPrincipal("cognito-identity.amazonaws.com",{
                "StringEquals": {
                    "cognito-identity.amazonaws.com:aud": admsIdentityPool.ref
                },
                "ForAnyValue:StringLike": {
                    "cognito-identity.amazonaws.com:amr": "authenticated"
                }
            }, "sts:AssumeRoleWithWebIdentity")
        )
        identitypoolAuthRole.attach_inline_policy(iam.Policy(self,"authPolicy",document=identitypoolAuthAssumeRolePolicyDoc))
        identitypoolUnauthRole = iam.Role(self, "IdentityPoolUnauthRole",
            assumed_by=iam.FederatedPrincipal("cognito-identity.amazonaws.com",{
                "StringEquals": {
                    "cognito-identity.amazonaws.com:aud": admsIdentityPool.ref
                },
                "ForAnyValue:StringLike": {
                    "cognito-identity.amazonaws.com:amr": "unauthenticated"
                }
            }, "sts:AssumeRoleWithWebIdentity")
        )
        identitypoolUnauthRole.attach_inline_policy(iam.Policy(self,"unauthPolicy",document=identitypoolAuthAssumeRolePolicyDoc))
        
        # Cognito Identity Pool Role Attachment
        cfn_identity_pool_role_attachment = cognito.CfnIdentityPoolRoleAttachment(self,
         "MyCfnIdentityPoolRoleAttachment",
            identity_pool_id=admsIdentityPool.ref,
            roles={
                "authenticated":identitypoolAuthRole.role_arn,
                "unauthenticated":identitypoolUnauthRole.role_arn,
            }
        )

        # API Gateway
        api = apigateway.RestApi(self, "search-api",
            description="ADMS Lambda search-api",
            rest_api_name="adms-search-api"
        )
        # API Gateway Authorizer
        apiAuth = apigateway.CognitoUserPoolsAuthorizer(self, "apiAuth",
            cognito_user_pools=[pool]
        )
        # API Gateway Method
        resource = api.root.add_resource("search")
        api.root.add_method("GET", apigateway.LambdaIntegration(search_api, proxy=True),
            request_parameters={"method.request.querystring.q":True},
            authorizer=apiAuth,
            authorization_type=apigateway.AuthorizationType.COGNITO,
            authorization_scopes=["email", "aws.cognito.signin.user.admin"],
            method_responses=[apigateway.MethodResponse(
                status_code="200",

                # the properties below are optional
                response_models={
                    "application/json": apigateway.Model.EMPTY_MODEL
                },
                response_parameters={
                    "method.response.header.Access-Control-Allow-Origin": True
                }
            )]
        )
        # IAM Policy Document
        adms_policyDoc = iam.PolicyDocument(
            statements=[
                iam.PolicyStatement(
                    actions=[
                        "logs:CreateLogGroup",
                        "logs:CreateLogStream",
                        "logs:PutLogEvents"
                    ],
                    resources=["arn:aws:logs:*:*:*"]
                ),
                iam.PolicyStatement(
                    actions=[
                        "logs:CreateLogStream",
                        "logs:PutLogEvents"
                    ],
                    resources=[
                        "arn:aws:logs:*:*:log-group:/aws/lambda/*:*"
                    ]
                ),
                iam.PolicyStatement(
                    actions=[
                        "s3:*",
                        "s3-object-lambda:*"
                    ],
                    resources=[
                        "arn:aws:s3:::"+bucket_front.bucket_name+"",
                        "arn:aws:s3:::"+bucket_raw.bucket_name+"",
                        "arn:aws:s3:::"+bucket_front.bucket_name+"/*",
                        "arn:aws:s3:::"+bucket_raw.bucket_name+"/*"
                    ]
                ),
                iam.PolicyStatement(
                    actions=[
                        "polly:*"
                    ],
                    resources=[
                        "*"
                    ]
                ),
                iam.PolicyStatement(
                    actions=[
                        "textract:*"
                    ],
                    resources=[
                        "*"
                    ]
                ),
                iam.PolicyStatement(
                    actions=[
                        "transcribe:*"
                    ],
                    resources=[
                        "*"
                    ]
                ),
                iam.PolicyStatement(
                    actions=[
                        "es:ESHttp*"
                    ],
                    resources=[
                        "*"
                    ]
                ),
                iam.PolicyStatement(
                    actions=[
                        "xray:PutTraceSegments",
                        "xray:PutTelemetryRecords"
                    ],
                    resources=[
                        "*"
                    ]
                ),
                iam.PolicyStatement(
                    actions=[
                        "ec2:CreateNetworkInterface",
                        "ec2:DescribeNetworkInterfaces",
                        "ec2:DeleteNetworkInterface"
                    ],
                    resources=[
                        "*"
                    ]
                ),
                iam.PolicyStatement(
                    actions=[
                        "lambda:InvokeFunction"
                    ],
                    resources=[
                        index_doc.function_arn+"*",
                        index_media.function_arn+"*",
                        search_api.function_arn+"*",
                        format_textract.function_arn+"*"
                    ]
                )
            ]
        )
        # IAM Policy
        adms_policy = iam.Policy(self,"adms-policy",document=adms_policyDoc)
        # IAM Policy Attachment
        format_textract.role.attach_inline_policy(iam.Policy(self,"format_textract_lambda-policy",document=adms_policyDoc))
        index_doc.role.attach_inline_policy(iam.Policy(self,"index_doc_lambda-policy",document=adms_policyDoc))
        index_media.role.attach_inline_policy(iam.Policy(self,"index_media_lambda-policy",document=adms_policyDoc))
        search_api.role.attach_inline_policy(iam.Policy(self,"search_api_lambda-policy",document=adms_policyDoc))

        # State Machine Role
        state_machine_role = iam.Role(self, "StateMachineRole",
            assumed_by=iam.ServicePrincipal("states.amazonaws.com")
        )
        state_machine_role.attach_inline_policy(adms_policy)

        # Load step function template file
        sfn_def = open("../../step-function/StateMachineTemplate.json", "r")

        # Step Functions
        cfn_state_machine = _aws_stepfunctions.CfnStateMachine(self, "admsStateMachine",
            role_arn=state_machine_role.role_arn,

            definition_string=sfn_def.read(),
            definition_substitutions={
                "OUTPUT_BUCKET":bucket_front.bucket_name,
                "LAMBDA_INDEX_MEDIA_ARN":index_media.function_arn,
                "LAMBDA_FORMAT_TEXTRACT_ARN":format_textract.function_arn,
                "LAMBDA_INDEX_DOC_ARN":index_doc.function_arn
            },
            state_machine_name="admsStateMachine",
            state_machine_type="STANDARD",
            tracing_configuration=_aws_stepfunctions.CfnStateMachine.TracingConfigurationProperty(
                enabled=True
            )
        )

        # Event Role
        event_role = iam.Role(self, "EventRole",
            assumed_by=iam.ServicePrincipal("events.amazonaws.com")
        )
        # Event Role Policy
        event_role_policy_doc = iam.PolicyDocument(
            statements=[
                iam.PolicyStatement(
                    actions=["states:StartExecution"],
                    resources= [cfn_state_machine.attr_arn]
                )]
        )
        event_role.attach_inline_policy(iam.Policy(self,"InvokeADMSStateMachine",document=event_role_policy_doc))
        # Event Rule
        rule = events.CfnRule(self, "adms-rule",
            description="adms-rule",
            event_pattern={
                "source": ["aws.s3"],
                "detail-type": ["Object Created"],
                "detail": {
                    "bucket": {
                    "name": [bucket_raw.bucket_name]
                    },
                    "object": {
                    "key": [{
                        "prefix": "input/"
                    }]
                    }
                }
            },
            name="adms-rule",
            role_arn=event_role.role_arn,
            targets=[events.CfnRule.TargetProperty(
                        arn=cfn_state_machine.attr_arn,
                        id="adms",
                        role_arn=event_role.role_arn)
                    ]
        )

        # S3 Config Map File
        json_template={
            "cognito": {
                "userPoolId":pool.user_pool_id,
                "clientId":poolClient.user_pool_client_id,
                "identityPoolId":admsIdentityPool.ref
            },
            "apigatewayendpoint": api.url,
            "bucket": {
                "region": region,
                "name": bucket_raw.bucket_name,
            }
        }
        config_file = s3_deploy.Source.data("scripts/config.js","window._config = "+ str(json_template)+";")
        
        # S3 Deployment
        deployment = s3_deploy.BucketDeployment(self, "DeployWebsite",
            sources=[
                    s3_deploy.Source.asset(os.path.join("front", '../../../sample-site')),
                    config_file
                ],
            destination_bucket=bucket_front,
            distribution=adms_dist
        )
        # Cognito UserPool User
        cfn_user_pool_user = cognito.CfnUserPoolUser(self, "MyCfnUserPoolUser",
            user_pool_id=pool.user_pool_id,

            desired_delivery_mediums=["EMAIL"],
            force_alias_creation=False,
            username="adms-user",
            user_attributes=[cognito.CfnUserPoolUser.AttributeTypeProperty(
                name="email",
                value=email
            ),
            cognito.CfnUserPoolUser.AttributeTypeProperty(
                name="email_verified",
                value="true"
            )]
        )
        aws_reset_passwd = cr.AwsCustomResource(self, "aws-reset-cognito-user-passwd",
            on_create=cr.AwsSdkCall(
                service="CognitoIdentityServiceProvider",
                action="adminSetUserPassword",
                parameters={
                    "UserPoolId": pool.user_pool_id,
                    "Username": "adms-user",
                    "Password": password,
                    "Permanent": True
                },
                physical_resource_id=cr.PhysicalResourceId.of("adms-user")
            ),
            policy=cr.AwsCustomResourcePolicy.from_sdk_calls(
                resources=cr.AwsCustomResourcePolicy.ANY_RESOURCE
            )
        )
