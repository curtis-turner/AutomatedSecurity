import boto3
import os
import json

#setup simple logging for INFO
import logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

#define the connection
ec2 = boto3.resource('ec2')

sns = boto3.client(service_name="sns")

def check_vpc(instance_id):
    return ec2.Instance(instance_id).vpc_id
    

def lambda_handler(event, context):
    print(json.dumps(event))
    # Use the filter() method of the instances collection to retrieve
    # all running EC2 instances.
    filters = [
        {
            'Name': 'instance-state-name', 
            'Values': ['running']
        }
    ]
    
    #filter instances for all running instances
    instances = ec2.instances.filter(Filters=filters)
    
    instancesToStop = []
	
    allowedTagKeys=['Name']
    missingTag = True
    
    for instance in instances:
        if instance.id not in os.environ['INSTANCE_WHITELIST']:
            count = len(allowedTagKeys)
            for x in allowedTagKeys:
                if instance.tags == None:
                    print('Instance has no tags...')
                    instancesToStop.append(instance.id)
                    break
                for i in instance.tags:
                    if x == i['Key']:
                        count -= 1
                        break

        if count > 0:
            print('Missing a tag...')
            instancesToStop.append(instance.id)
    '''
    if missinTag == True:
        instancesToStop.append(instance.id)
        
    missingTag = True
    '''
    
    message = 'This is a notification that EC2 instances were running without the required resource tags and have been stopped.\n\n'
    message += 'The following user started the instances: ' + event['detail']['userIdentity']['principalId'].split(':')[-1] + '\n\nBelow is a list of the instance IDs that were stopped fo reference.\n\n'
    for i in instancesToStop:
        vpc_id = check_vpc(i)
        message += 'Instance ID: ' + i +'\n'
        message += 'VPC ID: ' + vpc_id + '\n'

    #make sure there are actually instances to shut down. 
    if len(instancesToStop) > 0:
        #perform the shutdown
        ec2.instances.filter(InstanceIds=instancesToStop).stop()
        sns.publish(
            TopicArn = os.environ['SNS_TOPIC'],
            Subject = 'EC2 instance found with incorrect resource tags',
            Message = message
            )
    else:
        print('Nothing to see here')
