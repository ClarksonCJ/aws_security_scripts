import boto3
import json

client = boto3.client('ec2')

secgrps = client.describe_security_groups()


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
                if range['CidrIp'] == '0.0.0.0/0':
                    print(
                        "Egress rules for Security Group \"{}\", ID: {} are too open, consider restricting Egress rules to known IPs".format(
                            grp['GroupName'], grp['GroupId']))




security_group_egress_check(secgrps)
