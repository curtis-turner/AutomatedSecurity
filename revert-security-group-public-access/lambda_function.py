import os
import json
import boto3


# ===============================================================================
def lambda_handler(event, context):
    print(json.dumps(event))

    # Ensure that we have an event name to evaluate.
    if 'detail' not in event or ('detail' in event and 'eventName' not in event['detail']):
        return {"Result": "Failure", "Message": "Lambda not triggered by an event"}

    # Remove the rule only if the event was to authorize the ingress rule for the given
    # Check to ensure that the security group id is associated with the VPC ID specified in the Environment Variables
    sg_vpc = boto3.resource('ec2').SecurityGroup(event['detail']['requestParameters']['groupId']).vpc_id
    
    ipv4 = ''
    ipv6 = ''
    
    #if len(event['detail']['requestParameters']['ipPermissions']['items']) == 1:
    if event['detail']['requestParameters']['ipPermissions']['items'][0]['ipRanges'] and not event['detail']['requestParameters']['ipPermissions']['items'][0]['ipv6Ranges']:
        ipv4 = event['detail']['requestParameters']['ipPermissions']['items'][0]['ipRanges']['items'][0]['cidrIp']
    elif event['detail']['requestParameters']['ipPermissions']['items'][0]['ipv6Ranges'] and not  event['detail']['requestParameters']['ipPermissions']['items'][0]['ipRanges']:
        ipv6 = event['detail']['requestParameters']['ipPermissions']['items'][0]['ipv6Ranges']['items'][0]['cidrIpv6']
    else:
        ipv4 = event['detail']['requestParameters']['ipPermissions']['items'][0]['ipRanges']['items'][0]['cidrIp']
        ipv6 = event['detail']['requestParameters']['ipPermissions']['items'][0]['ipv6Ranges']['items'][0]['cidrIpv6']
            

    if (event['detail']['eventName'] == 'AuthorizeSecurityGroupIngress' and sg_vpc == os.environ['vpc_id'] and ipv4 == '0.0.0.0/0' or ipv6 == '::/0'):
        
        print('Removing SG changes...')
        result = revoke_security_group_ingress(event['detail'])
        
        group_id = event['detail']['requestParameters']['groupId']
        
        print('Sending notification...')
        message = "Security Group: {} - was modified but changes have been removed. Check EC2 security groups to confirm.\n\nLambda Function -- Remediate-VPC-SG-External-Access -- AUTO-MITIGATED: Ingress rule removed from security group: {}.\n\nModification of SG was made by User: {}.\n\nSecurity Group Permissions Added:\n{}".format(
            result['group_id'],
            result['group_id'],
            result['user_name'].split('/')[-1],
            json.dumps(result['ip_permissions']),
        )

        boto3.client('sns').publish(TargetArn = os.environ['sns_topic_arn'], Message = message, Subject = "EC2 - Security Group: {} - Auto-Mitigation Successful".format(result['group_id']) )

# ===============================================================================
def revoke_security_group_ingress(event_detail):
    request_parameters = event_detail['requestParameters']

    # Build the normalized IP permission JSON struture.
    ip_permissions = normalize_paramter_names(request_parameters['ipPermissions']['items'])

    response = boto3.client('ec2').revoke_security_group_ingress(
        GroupId=request_parameters['groupId'],
        IpPermissions=ip_permissions
    )
    
    # Build the result
    result = {}
    result['group_id'] = request_parameters['groupId']
    result['user_name'] = event_detail['userIdentity']['arn']
    result['ip_permissions'] = ip_permissions

    return result


# ===============================================================================
def normalize_paramter_names(ip_items):
    # Start building the permissions items list.
    new_ip_items = []
    
    ipv4_ranges = []
    ipv6_ranges = []
    
    # First, build the basic parameter list.
    for ip_item in ip_items:

        new_ip_item = {
            "IpProtocol": ip_item['ipProtocol'],
            "FromPort": ip_item['fromPort'],
            "ToPort": ip_item['toPort']
        }
        


        # CidrIp or CidrIpv6 (IPv4 or IPv6) or both?
        if ip_item['ipRanges']:
            #we only have ipv4 range
            ipv4_range_list_name = 'ipRanges'
            ipv4_address_value = 'cidrIp'
            ipv4_range_list_name_capitalized = 'IpRanges'
            ipv4_address_value_capitalized = 'CidrIp'
            
            for item in ip_item[ipv4_range_list_name]['items']:
                ipv4_ranges.append(
                    {ipv4_address_value_capitalized: item[ipv4_address_value]}
                    )
            
            new_ip_item[ipv4_range_list_name_capitalized] = ipv4_ranges
            
            new_ip_items.append(new_ip_item)

            
        elif ip_item['ipv6Ranges']:
            #we only have ipv6 ranges
            ipv6_range_list_name = 'ipv6Ranges'
            ipv6_address_value = 'cidrIpv6'
            ipv6_range_list_name_capitalized = 'Ipv6Ranges'
            ipv6_address_value_capitalized = 'CidrIpv6'
            
            for item in ip_item[ipv6_range_list_name]['items']:
                ipv6_ranges.append(
                    {ipv6_address_value_capitalized: item[ipv6_address_value]}
                    )
                    
            new_ip_item[ipv6_range_list_name_capitalized] = ipv6_ranges
            
            new_ip_items.append(new_ip_item)
            
        else:
            print('check event formatting...')
        
        
    return new_ip_items