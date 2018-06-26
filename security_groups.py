import boto3
import json

resource = boto3.resource('ec2', region_name='eu-west-1')
client = boto3.client('ec2')

def header_message():
    print('AWS Security Group Analysis')
    print('------------------------------------------------------------------------')
    print('[+] Author: Chris Clarkson')
    print('[+] Company: CJC Software Solutions Ltd.')
    print('[+] License: MIT')
    print('[+] Python Script to Analyse the Security Groups of an AWS Account')
    print('[+] usage: security_groups.py')
    print('------------------------------------------------------------------------')
    print()

def security_group_egress_check(groups):
    '''
    Method to check the Security Egress rules for a list of security Groups
    :param groups:
    Groups returned by AWS API
    :return:
    '''
    for grp in groups:
        for egress in grp['IpPermissionsEgress']:
            for range in egress['IpRanges']:
                if  range['CidrIp'] == '0.0.0.0/0':
                    try:
                        print(
                            "[+]--> Egress rules for Security Group \"{}\", ID: {} are too open ({}), consider restricting Egress rules to known IPs".format(
                                grp['GroupName'], grp['GroupId'], range['CidrIp']))
                    except:
                        pass

def security_group_ingress_check(groups):
    '''
    Method to check the Security ingress rules for a list of security groups
    :param groups:
    :return:
    '''
    for group in groups:
        for grp in group['IpPermissions']:
            for range in grp['IpRanges']:
                if range['CidrIp'] == '0.0.0.0/0':
                    try:
                        print(
                            "[+]--> Ingress Rules for Security group \"{}\", ID: {} allow traffic from Port: {} to Port: {} from Any IP (0.0.0.0/0).".format(
                                group['GroupName'], group['GroupId'], grp['FromPort'], grp['ToPort']
                            )
                        )
                    except:
                        pass


def vpc_instance_lookup(vpc):
    for subnet in vpc.subnets.all():
        for instance in subnet.instances.all():
            instancename = next((tag['Value'] for tag in instance.tags if tag['Key'] == 'Name'), None)
            print('---------------------')
            print("[+] Assigned Instance: {}".format(instancename))
            print('---------------------')
            groupids = list((grp['GroupId'] for grp in instance.security_groups))
            grps = client.describe_security_groups(GroupIds=groupids)
            security_groups = grps['SecurityGroups']
            security_group_egress_check(security_groups)
            security_group_ingress_check(security_groups)
            print()

header_message()
filters = [{'Name': 'tag:Name', 'Values': ['*']}]
for vpc in resource.vpcs.filter(Filters=filters):
    vpcname = next((tag['Value'] for tag in vpc.tags if tag['Key'] == 'Name'), None)
    print('---------------------------------------------------------------')
    print("VPC: {}".format(vpcname))
    print('---------------------------------------------------------------')
    secgrps = vpc_instance_lookup(vpc)
