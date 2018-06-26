import boto3
import json

client = boto3.client('ec2')

secgrps = client.describe_security_groups()

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
    for grp in groups['SecurityGroups']:
        for egress in grp['IpPermissionsEgress']:
            for range in egress['IpRanges']:
                if  range['CidrIp'] == '0.0.0.0/0' and egress['IpProtocol'] == '-1':
                    print(
                        "[+] Egress rules for Security Group \"{}\", ID: {} are too open, consider restricting Egress rules to known IPs".format(
                            grp['GroupName'], grp['GroupId']))



header_message()
security_group_egress_check(secgrps)
