import boto3
import json
import os
import types

EVERYONE_URI = 'http://acs.amazonaws.com/groups/global/AllUsers'
AUTHENTICATED_URI = 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'

def isAuthorizedUser(userId):
    #check is user is part of the admin group that is allowed to make S3 buckets public
    iam = boto3.client('iam')
    group = iam.get_group(GroupName = os.environ['IAM_GROUP'])
    
    #display group data for debugging
    #print(group)
    
    for user in group['Users']:
        if userId in user.values():
            return True

def remediateAccess(bucket):
    #remove the public access from the bucket policy or acl
    
    s3 = boto3.resource('s3')
    bucket_acl = s3.BucketAcl(bucket)
    
    response = bucket_acl.put(
        ACL = 'private'
    )

def hasPublicAccess(grant):
    #determine if the bucket has any public access
    if len(grant) > 1:
        for grantee in grant:
            try:
                if 'URI' in grantee['Grantee']:
                    if grantee['Grantee']['URI'] == EVERYONE_URI or grantee['Grantee']['URI'] == AUTHENTICATED_URI:
                        if grantee['Permission'] == 'READ' or grantee['Permission'] == 'WRITE' or grantee['Permission'] == 'READ_ACP' or grantee['Permission'] == 'WRITE_ACP':
                            return True
            except:
                return False
    else:
        if grant[0] == 'private':
            return False

def notify(bucket, userId, userName, bucketPolicy=''):
    if isAuthorizedUser(userId):
        message = 'The following user: ' + userName  + ' -  made changes to bucket: ' + bucket + '. Allowing PUBLIC ACCESS to the bucket.\n\nThe user: ' + userName + ' - is AUTHORIZED to make buckets public.\n\n'
        if bucketPolicy != '':
            message += 'The Bucket Policy is attached below for reference.\n\n' + json.dumps(bucketPolicy)
        subject = 'S3 Bucket Made Public by AUTHORIZED User'
    else:
        message = 'The following user: ' + userName + ' - made changes to bucket: ' + bucket + '. Allowing PUBLIC ACCESS to the bucket.\n\nThe user: ' + userName + ' - is  NOT AUTHORIZED to make buckets public.\n\n All changes have been removed.\n\n'
        if bucketPolicy != '':
            message += 'The Bucket Policy is attached below for reference.\n\n' + json.dumps(bucketPolicy)
        subject = 'S3 Bucket Made Public by UNAUTHORIZED User'
    
    sns = boto3.client('sns')
    
    sentMessage = sns.publish(
        TopicArn = os.environ['SNS_TOPIC'],
        Message = message,
        Subject = subject
        )
        
        
def lambda_handler(event, context):
    #dump event for debugging
    print(json.dumps(event))
    
    eventName = event['detail']['eventName']
    bucket = event['detail']['requestParameters']['bucketName']
    
    if event['detail']['userIdentity']['type'] == 'IAMUser':
        userId = event['detail']['userIdentity']['principalId']
        userName = event['detail']['userIdentity']['userName']
    
    if event['detail']['userIdentity']['type'] == 'AssumedRole':
        userId = event['detail']['userIdentity']['sessionContext']['sessionIssuer']['principalId']
        userName = event['detail']['userIdentity']['arn'].split('/')[-1]
    
    #check eventName to determine where to look for public access. either in the ACL or the BucketPolicy.
    #Once that is determined send a notification. If the user is NOT Authorized we will remove the public access
    if eventName == 'PutBucketAcl':
        if 'AccessControlPolicy' in event['detail']['requestParameters'].keys():
            grant = event['detail']['requestParameters']['AccessControlPolicy']['AccessControlList']['Grant']
        
        if hasPublicAccess(grant):
            if isAuthorizedUser(userId):
                notify(bucket, userId, userName)
            else:
                #auto remediate
                remediateAccess(bucket)
                notify(bucket, userId, userName)
                
    elif eventName == 'PutBucketPolicy':
        
        bucket_policy = event['detail']['requestParameters']['bucketPolicy']
        
        if any(policy['Principal'] == '*' for policy in bucket_policy['Statement']):
            if isAuthorizedUser(userId):
                notify(bucket, userId, userName, bucket_policy)
            else:
                #remove the bucket polocy because the user is not authorized to provide public access
                s3 = boto3.resource('s3')
                response = s3.BucketPolicy(bucket).delete()
                notify(bucket, userId, userName, bucket_policy)
            
        
    elif eventName == 'CreateBucket':
        if 'x-amz-acl' in event['detail']['requestParameters'].keys():
            grant = event['detail']['requestParameters']['x-amz-acl']
        
        if hasPublicAccess(grant):
            if isAuthorizedUser(userId):
                notify(bucket, userId, userName)
            else:
                #auto remediate
                remediateAccess(bucket)
                notify(bucket, userId, userName)
    
    else:
        print('eventName is not correct.')