import json
import os
import boto3
import datetime

def notify(functionName,userName):
    sns = boto3.client('sns')
    
    sns.publish(
        TopicArn = os.environ['SNS_TOPIC'],
        Message = 'New Lambda Function created by: {}.\n\nNew Lambda Function created with name: {}.\n\nAdding todays date to the "Created" tag value.'.format(userName, functionName),
        Subject = 'Lambda Function Created'
    )
    
def tagResource(date, arn):
    lambda_ = boto3.client('lambda')
    
    response = lambda_.tag_resource(
        Resource = arn,
        Tags = {
            'Created': date
        }
    )
    
def check_vpc(fn_name):
    lambda_ = boto3.client('lambda')
    
    response = lambda_.get_function(
            FunctionName = fn_name
        )
    
    if 'VpcConfig' in response:
        print('Lambda is associated with VPC...')
        vpc_id = response['VpcConfig']['VpcId']
        return vpc_id
        
    print(json.dumps(response))
        
def lambda_handler(event, context):
    #output the event json for debugging
    print(json.dumps(event))
    
    if 'CreateFunction' in event['detail']['eventName']:
        #get current date of lambda function execution
        date = datetime.date.today().strftime('%m-%d-%Y')
        
        #get the function arn that we will need to add tag to
        functionArn = event['detail']['responseElements']['functionArn']
        
        #get function name to send in the notification
        functionName = event['detail']['requestParameters']['functionName']
        
        #get user name from the event
        userName = event['detail']['userIdentity']['principalId'].split(':')[1]
        
        check_vpc(functionName)
        
        #add the date to the Create tag value
        tagResource(date, functionArn)
        
        #send notification
        notify(functionName,userName)