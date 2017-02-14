######################################################################################################################
#  Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.                                           #
#                                                                                                                    #
#  Licensed under the Amazon Software License (the "License"). You may not use this file except in compliance        #
#  with the License. A copy of the License is located at                                                             #
#                                                                                                                    #
#      http://aws.amazon.com/asl/                                                                                    #
#                                                                                                                    #
#  or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES #
#  OR CONDITIONS OF ANY KIND, express or implied. See the License for the specific language governing permissions    #
#  and limitations under the License.                                                                                #
######################################################################################################################

import boto3
from botocore.client import Config
import xmltodict
import ast
import logging
import datetime, sys, json, urllib2, urllib, re

log = logging.getLogger()
log.setLevel(logging.INFO)

bucket_name = '%BUCKET_NAME%'
bucket_prefix = '%PREFIX%'
config_file_ext = '.conf'


# Resource tags come in the format of [{"Key": "Tag1", "Value":"Tag1value"},{"Key":"Tag2","Value":"Tag2value"}]
# This function converts the array of Key/Value dicts to a single tag dictionary
def getTags(tags):
    tag_s = {}
    for tag in tags:
        tag_s[tag['Key']] = tag['Value']
    return tag_s


# This function determines whether or not Anonymous data should be send and, if so, sends it
def sendAnonymousData(config, vgwTags, region, vpn_connections):
    # Code to send anonymous data if enabled
    if config['SENDDATA'] == "Yes":
        log.debug("Sending Anonymous Data")
        dataDict = {}
        postDict = {}
        dataDict['region'] = region
        dataDict['vpn_connections'] = vpn_connections
        # should be using hub_tag_value_create / hub_tag_value_delete
        if vgwTags[config['HUB_TAG']] == config['HUB_TAG_VALUE_CREATE']:
            dataDict['status'] = "create"
        else:
            dataDict['status'] = "delete"

        dataDict['preferred_path'] = vgwTags.get(config['PREFERRED_PATH_TAG'],
                                                 'none')
        dataDict['version'] = '3'
        postDict['Data'] = dataDict
        postDict['TimeStamp'] = str(datetime.datetime.now())
        postDict['Solution'] = 'SO0001'
        postDict['UUID'] = config['UUID']
        # API Gateway URL to make HTTP POST call
        url = 'https://metrics.awssolutionsbuilder.com/generic'
        data = json.dumps(postDict)
        log.info(data)
        headers = {'content-type': 'application/json'}
        req = urllib2.Request(url, data, headers)
        rsp = urllib2.urlopen(req)
        rspcode = rsp.getcode()
        content = rsp.read()
        log.debug("Response from APIGateway: %s, %s", rspcode, content)


    # This function creates/deletes CustomerGateways
def customerGateways(config, ec2, action):
    if action == 'create':
        # Create Customer Gateways (will create CGWs if they do not exist, otherwise, the API calls are ignored)
        log.info('Creating Customer Gateways with IP %s, %s', config['EIP1'],
                 config['EIP2'])
        cg1 = ec2.create_customer_gateway(
            Type='ipsec.1', PublicIp=config['EIP1'], BgpAsn=config['BGP_ASN'])
        ec2.create_tags(
            Resources=[cg1['CustomerGateway']['CustomerGatewayId']],
            Tags=[{
                'Key': 'Name',
                'Value': 'Transit VPC Endpoint1'
            }])
        cg2 = ec2.create_customer_gateway(
            Type='ipsec.1', PublicIp=config['EIP2'], BgpAsn=config['BGP_ASN'])
        ec2.create_tags(
            Resources=[cg2['CustomerGateway']['CustomerGatewayId']],
            Tags=[{
                'Key': 'Name',
                'Value': 'Transit VPC Endpoint2'
            }])
        log.info('Created Customer Gateways: %s, %s',
                 cg1['CustomerGateway']['CustomerGatewayId'],
                 cg2['CustomerGateway']['CustomerGatewayId'])
        return cg1, cg2
    elif action == 'delete':
        log.info('Deleting Customer Gateways with IP %s, %s', config['EIP1'],
                 config['EIP2'])
        # Attempt to clean up the CGW. This will only succeed if the CGW has no
        # VPN connections are deleted
        cgw_ips = [config['EIP1'], config['EIP2']]

        for ip in cgw_ips:
            cgw_info = ec2.describe_customer_gateways(Filters=[{
                'Name':
                'ip-address',
                'Values': [ip]
            }])

            try:
                if len(cgw_info['CustomerGateways']) == 1:
                    cgw_id = cgw_info['CustomerGateways'][0][
                        'CustomerGatewayId']
                    ec2.delete_customer_gateway(CustomerGatewayId=cgw_id)

                log.info(
                    "Deleted %s [PublicIp=%s] since it has no VPN connections left",
                    cgw_id, ip)
            except:
                log.info("%s [PublicIp=%s] still has existing VPN connections",
                         ip)


# This Function returns a dictionary of VirtualGateways with VPNConnections
# to create and delete
def getVirtualGateways(vgw_s, vpn_s, config):
    hub_tag_key = config.get('HUB_TAG')
    hub_tag_value_create = config.get('HUB_TAG_VALUE_CREATE')
    hub_tag_value_delete = config.get('HUB_TAG_VALUE_DELETE')
    log.info('Processing VirtualGateways and VPNConnections for Hub Tag %s/%s',
             hub_tag_value_create, hub_tag_value_delete)

    vgws = dict(create={}, delete={})
    vgw_vpns = {}
    # Create Mapping of VirtualConnections to VirtualGateway
    for vpn in vpn_s:
        vgw_id = vpn['VpnGatewayId']
        if not vgw_vpns.get(vgw_id):
            vgw_vpns[vgw_id] = []
        vpn['Tags'] = getTags(vpn['Tags'])
        # convert CustomerGatewayConfiguration XML dict
        vpn['CustomerGatewayConfiguration'] = xmltodict.parse(
            vpn['CustomerGatewayConfiguration'])
        vgw_vpns[vgw_id].append(vpn)

    # Process all the VGWs in the region
    for vgw in vgw_s:
        vgw_id = vgw['VpnGatewayId']
        # Check to see if the VGW has tags, if not, then we should skip it
        if vgw.get('Tags', '') == '':
            continue

        # Put all of the VGW tags into a dict for easier processing
        vgwTags = getTags(vgw['Tags'])

        # Configure HUB_TAG if it is not set already (for untagged VGWs)
        vgwTags[hub_tag_key] = vgwTags.get(hub_tag_key, '')
        vgw['Tags'] = vgwTags
        # Add VPNConnection to VirtualGateway
        vgw['VpnConnections'] = vgw_vpns.get(vgw_id)

        # Determine if VGW is tagged as a spoke
        # and add accordingly to create/delete
        if vgwTags[hub_tag_key] == hub_tag_value_create:
            vgws['create'][vgw_id] = vgw
        elif vgwTags[hub_tag_key] == hub_tag_value_delete:
            vgws['delete'][vgw_id] = vgw

    log.info('Processed VirtualGateways and VPNConnections for Hub Tag %s/%s',
             hub_tag_value_create, hub_tag_value_delete)
    return vgws


# This Function Creates VPNConnections for a VirtualGateway
# and upload JSON configuration to S3 bucket
def createVirtualGatewayVpn(account_id, ec2, s3, cg1, cg2, config, vgw):
    region = ec2._client_config.region_name
    hub_tag_key = config.get('HUB_TAG')
    hub_tag_value_create = config.get('HUB_TAG_VALUE_CREATE')
    planet_tag_key = config.get('PLANET_TAG')

    vgw_id = vgw['VpnGatewayId']
    planet = vgw['Tags'].get(planet_tag_key)
    preferred_path = vgw['Tags'].get(config['PREFERRED_PATH_TAG'], 'none')
    vpn_id_1 = False
    vpn_id_2 = False

    log.info("Checking VPNConnections for VirtualGateway %s", vgw_id)
    # Check to see if the VGW already has Transit VPC VPN Connections
    if vgw['VpnConnections']:
        for vpn in vgw['VpnConnections']:
            vpn_id = vpn['VpnConnectionId']
            vpn_tags = vpn.get('Tags')

            if vpn_tags.get('Name') == (
                    vgw_id + '-to-Transit-VPC CSR1') and vpn_tags.get(
                        hub_tag_key) == hub_tag_value_create and vpn_tags.get(
                            'transitvpc:endpoint') == 'CSR1':
                vpn_id_1 = vpn_id
                vpn_1 = vpn
            elif vpn_tags.get('Name') == (
                    vgw_id + '-to-Transit-VPC CSR2') and vpn_tags.get(
                        hub_tag_key) == hub_tag_value_create and vpn_tags.get(
                            'transitvpc:endpoint') == 'CSR2':
                vpn_id_2 = vpn_id
                vpn_2 = vpn
            else:
                log.info("skipping poller create vpn connection id %s" %
                         vpn_id)

    # Need to create VPN connections if this is a spoke VGW and no VPN
    # connections already exist for CSR1 and CSR2
    if not vpn_id_1:
        log.info("Creating CSR1 VPNConnection for VirtualGateway %s", vgw_id)
        # Create and tag first VPN connection
        vpn_1 = ec2.create_vpn_connection(
            Type='ipsec.1',
            CustomerGatewayId=cg1['CustomerGateway']['CustomerGatewayId'],
            VpnGatewayId=vgw['VpnGatewayId'],
            Options={'StaticRoutesOnly': False})
        vpn_1 = vpn_1['VpnConnection']
        vpn_id_1 = vpn_1['VpnConnectionId']
        ec2.create_tags(
            Resources=[vpn_id_1],
            Tags=[{
                'Key': 'Name',
                'Value': vgw_id + '-to-Transit-VPC CSR1'
            }, {
                'Key': hub_tag_key,
                'Value': hub_tag_value_create
            }, {
                'Key': 'transitvpc:endpoint',
                'Value': 'CSR1'
            }])
        log.info("Created CSR1 VPNConnection %s for VirtualGateway %s",
                 vpn_id_1, vgw_id)
        vpn_1['CustomerGatewayConfiguration'] = xmltodict.parse(
            vpn_1['CustomerGatewayConfiguration'])
    else:
        log.info(
            "Already Existing CSR1 VPNConnection %s for VirtualGateway %s",
            vpn_id_1, vgw_id)

    if not vpn_id_2:
        log.info("Creating CSR2 VPNConnection for VirtualGateway %s", vgw_id)
        # Create and tag second VPN connection
        vpn_2 = ec2.create_vpn_connection(
            Type='ipsec.1',
            CustomerGatewayId=cg2['CustomerGateway']['CustomerGatewayId'],
            VpnGatewayId=vgw['VpnGatewayId'],
            Options={'StaticRoutesOnly': False})
        vpn_2 = vpn_2['VpnConnection']
        vpn_id_2 = vpn_2['VpnConnectionId']
        ec2.create_tags(
            Resources=[vpn_id_2],
            Tags=[{
                'Key': 'Name',
                'Value': vgw_id + '-to-Transit-VPC CSR2'
            }, {
                'Key': hub_tag_key,
                'Value': hub_tag_value_create
            }, {
                'Key': 'transitvpc:endpoint',
                'Value': 'CSR2'
            }])
        log.info("Created CSR1 VPNConnection %s for VirtualGateway %s",
                 vpn_id_2, vgw_id)
        vpn_2['CustomerGatewayConfiguration'] = xmltodict.parse(
            vpn_2['CustomerGatewayConfiguration'])
    else:
        log.info(
            "Already Existing CSR2 VPNConnection %s for VirtualGateway %s",
            vpn_id_2, vgw_id)

    log.info("Creating CSR1 VPNConnection %s Configuration", vpn_id_1)
    # Creating CSR1 VPNConnection Configuration
    vpn_config_1 = dict(
        vpn_connection_id=vpn_id_1,
        transit_vpc_config={},
        ipsec_tunnels=vpn_1['CustomerGatewayConfiguration']['vpn_connection'][
            'ipsec_tunnel'])

    vpn_config_1['transit_vpc_config'] = {
        "preferred_path": preferred_path,
        "account_id": account_id,
        "vpn_endpoint": "CSR1",
        "status": "create",
        "planet": planet,
        "region": region,
        "customer_gateway_id": vpn_1['CustomerGatewayId'],
        "vpn_connection_type": vpn_1['Type'],
        "vpn_gateway_id": vpn_1['VpnGatewayId']
    }

    log.info("Creating CSR2 VPNConnection %s Configuration", vpn_id_2)
    # Creating CSR2 VPNConnection Configuration
    vpn_config_2 = dict(
        vpn_connection_id=vpn_id_2,
        transit_vpc_config={},
        ipsec_tunnels=vpn_2['CustomerGatewayConfiguration']['vpn_connection'][
            'ipsec_tunnel'])

    vpn_config_2['transit_vpc_config'] = {
        "preferred_path": preferred_path,
        "account_id": account_id,
        "vpn_endpoint": "CSR2",
        "status": "create",
        "planet": planet,
        "region": region,
        "customer_gateway_id": vpn_2['CustomerGatewayId'],
        "vpn_connection_type": vpn_2['Type'],
        "vpn_gateway_id": vpn_2['VpnGatewayId']
    }

    # Generate JSON Configuration
    log.info("Generating CSR1 VPNConnection %s JSON Configuration", vpn_id_1)
    vpn_config_1 = json.dumps(vpn_config_1, indent=2)
    log.info("Generating CSR2 VPNConnection %s JSON Configuration", vpn_id_2)
    vpn_config_2 = json.dumps(vpn_config_2, indent=2)

    #Put CSR1 config in S3
    log.info("Push CSR1 VPNConnection %s JSON Configuration to S3", vpn_id_1)
    s3.put_object(
        Body=str.encode(vpn_config_1),
        Bucket=bucket_name,
        Key=bucket_prefix + 'CSR1/' + region + '-' + vpn_id_1 +
        config_file_ext,
        ACL='bucket-owner-full-control',
        ServerSideEncryption='aws:kms',
        SSEKMSKeyId=config['KMS_KEY'])
    log.info("Pushed CSR1 VPNConnection %s JSON Configuration to S3", vpn_id_1)

    #Put CSR2 config in S3
    log.info("Push CSR2 VPNConnection %s JSON Configuration to S3", vpn_id_2)
    s3.put_object(
        Body=str.encode(vpn_config_2),
        Bucket=bucket_name,
        Key=bucket_prefix + 'CSR2/' + region + '-' + vpn_id_2 +
        config_file_ext,
        ACL='bucket-owner-full-control',
        ServerSideEncryption='aws:kms',
        SSEKMSKeyId=config['KMS_KEY'])
    log.info("Pushed CSR2 VPNConnection %s JSON Configuration to S3", vpn_id_2)

    # send metrics anonymous data
    sendAnonymousData(config, vgw['Tags'], region, 2)


# This Function Deletes VPNConnections for a VirtualGateway
# and upload JSON configuration to S3 bucket
def deleteVirtualGatewayVpn(account_id, ec2, s3, config, vgw):
    region = ec2._client_config.region_name
    hub_tag_key = config.get('HUB_TAG')
    hub_tag_value_delete = config.get('HUB_TAG_VALUE_DELETE')
    planet_tag_key = config.get('PLANET_TAG')

    vgw_id = vgw['VpnGatewayId']
    planet = vgw['Tags'].get(planet_tag_key)
    preferred_path = vgw['Tags'].get(config['PREFERRED_PATH_TAG'], 'none')
    vpn_id_1 = False
    vpn_id_2 = False

    log.info("Checking VPNConnections for VirtualGateway %s", vgw_id)
    # Check to see if the VGW already has Transit VPC VPN Connections
    if vgw['VpnConnections']:
        for vpn in vgw['VpnConnections']:
            vpn_id = vpn['VpnConnectionId']
            vpn_tags = vpn.get('Tags')
            if vpn_tags.get('Name') == (
                    vgw_id + '-to-Transit-VPC CSR1'
            ) and vpn_tags.get('transitvpc:endpoint') == 'CSR1':
                vpn_id_1 = vpn_id
                vpn_1 = vpn
            elif vpn_tags.get('Name') == (
                    vgw_id + '-to-Transit-VPC CSR2'
            ) and vpn_tags.get('transitvpc:endpoint') == 'CSR2':
                vpn_id_2 = vpn_id
                vpn_2 = vpn
            else:
                log.info("skipping poller delete vpn connection id %s" %
                         vpn_id)

    # Upload CSR1 VPNConnection configuration to S3 and Delete VPNConnection
    if vpn_id_1:
        log.info("Creating CSR1 VPNConnection %s Transit VPC Configuration",
                 vpn_id_1)
        # Creating CSR1 VPNConnection Configuration
        vpn_config_1 = dict(
            vpn_connection_id=vpn_id_1,
            transit_vpc_config={},
            ipsec_tunnels=vpn_1['CustomerGatewayConfiguration'][
                'vpn_connection']['ipsec_tunnel'])

        vpn_config_1['transit_vpc_config'] = {
            "preferred_path": preferred_path,
            "account_id": account_id,
            "vpn_endpoint": "CSR1",
            "status": "delete",
            "planet": planet,
            "region": region,
            "customer_gateway_id": vpn_1['CustomerGatewayId'],
            "vpn_connection_type": vpn_1['Type'],
            "vpn_gateway_id": vpn_1['VpnGatewayId']
        }

        log.info("Generating CSR1 VPNConnection %s JSON Configuration",
                 vpn_id_1)
        vpn_config_1 = json.dumps(vpn_config_1, indent=2)
        log.info("Generated CSR1 VPNConnection %s JSON Configuration",
                 vpn_id_1)

        log.info("Push CSR1 VPNConnection %s JSON Configuration to S3",
                 vpn_id_1)
        s3.put_object(
            Body=str.encode(vpn_config_1),
            Bucket=bucket_name,
            Key=bucket_prefix + 'CSR1/' + region + '-' + vpn_id_1 +
            config_file_ext,
            ACL='bucket-owner-full-control',
            ServerSideEncryption='aws:kms',
            SSEKMSKeyId=config['KMS_KEY'])
        log.info("Pushed CSR1 VPNConnection %s JSON Configuration to S3",
                 vpn_id_1)

        log.info("Deleting CSR1 VPNConnection %s for VirtualGateway %s",
                 vpn_id_1, vgw_id)
        ec2.delete_vpn_connection(VpnConnectionId=vpn_id_1)
        log.info("Deleted CSR1 VPNConnection %s for VirtualGateway %s",
                 vpn_id_1, vgw_id)
    else:
        log.info("Already Deleted CSR1 VPNConnection %s for VirtualGateway %s",
                 vpn_id_1, vgw_id)

    # Upload CSR2 VPNConnection configuration to S3 and Delete VPNConnection
    if vpn_id_2:
        log.info("Creating CSR2 VPNConnection %s Transit VPC Configuration",
                 vpn_id_2)
        vpn_config_2 = dict(
            vpn_connection_id=vpn_id_2,
            transit_vpc_config={},
            ipsec_tunnels=vpn_2['CustomerGatewayConfiguration'][
                'vpn_connection']['ipsec_tunnel'])

        vpn_config_2['transit_vpc_config'] = {
            "preferred_path": preferred_path,
            "account_id": account_id,
            "vpn_endpoint": "CSR2",
            "status": "delete",
            "planet": planet,
            "region": region,
            "customer_gateway_id": vpn_1['CustomerGatewayId'],
            "vpn_connection_type": vpn_1['Type'],
            "vpn_gateway_id": vpn_1['VpnGatewayId']
        }

        log.info("Generating CSR2 VPNConnection %s JSON Configuration",
                 vpn_id_2)
        vpn_config_2 = json.dumps(vpn_config_2, indent=2)

        log.info("Push CSR2 VPNConnection %s JSON Configuration to S3",
                 vpn_id_2)
        s3.put_object(
            Body=str.encode(vpn_config_2),
            Bucket=bucket_name,
            Key=bucket_prefix + 'CSR2/' + region + '-' + vpn_id_2 +
            config_file_ext,
            ACL='bucket-owner-full-control',
            ServerSideEncryption='aws:kms',
            SSEKMSKeyId=config['KMS_KEY'])
        log.info("Pushed CSR2 VPNConnection %s JSON Configuration to S3",
                 vpn_id_2)

        log.info("Deleting CSR2 VPNConnection %s for VirtualGateway %s",
                 vpn_id_2, vgw_id)
        ec2.delete_vpn_connection(VpnConnectionId=vpn_id_2)
        log.info("Deleted CSR2 VPNConnection %s for VirtualGateway %s",
                 vpn_id_2, vgw_id)
    else:
        log.info("Already Deleted CSR1 VPNConnection %s for VirtualGateway %s",
                 vpn_id_1, vgw_id)

    # send metrics anonymous data
    sendAnonymousData(config, vgw['Tags'], region, 1)


def lambda_handler(event, context):
    # Figure out the account number by parsing this function's ARN
    account_id = re.findall(':(\d+):', context.invoked_function_arn)[0]
    # Retrieve Transit VPC configuration from transit_vpn_config.txt
    s3 = boto3.client('s3', config=Config(signature_version='s3v4'))
    log.info('Getting config file %s/%s%s', bucket_name, bucket_prefix,
             'transit_vpc_config.txt')
    s3content = s3.get_object(
        Bucket=bucket_name,
        Key=bucket_prefix + 'transit_vpc_config.txt')['Body'].read()
    config = ast.literal_eval(s3content)
    config['HUB_TAG'] = config.get('HUB_TAG') or 'transitvpc:spoke'
    config['HUB_TAG_VALUE_CREATE'] = config.get(
        'HUB_TAG_VALUE_CREATE') or 'create'
    config['HUB_TAG_VALUE_DELETE'] = config.get(
        'HUB_TAG_VALUE_DELETE') or 'delete'
    config['PLANET_TAG'] = config.get('PLANET_TAG') or 'transitvpc:planet'
    config['PREFERRED_PATH_TAG'] = config.get(
        'PREFERRED_PATH_TAG') or 'transitvpc:preferred-path'

    hub_tag_key = config.get('HUB_TAG')
    hub_tag_value_create = config.get('HUB_TAG_VALUE_CREATE')
    hub_tag_value_delete = config.get('HUB_TAG_VALUE_DELETE')

    log.info('Retrieved IP of transit VPN gateways: %s, %s', config['EIP1'],
             config['EIP2'])
    # Get list of regions so poller can look for VGWs in all regions
    ec2 = boto3.client('ec2', region_name='us-east-1')
    regions = ec2.describe_regions()
    for region in regions['Regions']:
        # Get region name for the current region
        region = region['RegionName']
        log.info('Checking region: %s', region)
        # Create EC2 connection to this region to get list of VGWs
        ec2 = boto3.client('ec2', region_name=region)
        # Get list of all VGWs in the region
        vgws = ec2.describe_vpn_gateways(Filters=[{
            'Name':
            'state',
            'Values': ['available', 'attached', 'detached']
        }])
        # Get list of Transit VPC tagged VPN connections in the region as well
        vpns = ec2.describe_vpn_connections(Filters=[{
            'Name':
            'state',
            'Values': ['available', 'pending', 'deleting']
        }, {
            'Name':
            'tag:' + hub_tag_key,
            'Values': [hub_tag_value_create]
        }])

        # Get VirtualGateways
        vpn_gws = getVirtualGateways(vgws['VpnGateways'],
                                     vpns['VpnConnections'], config)
        # List of VirtualGateways VPNConnections and CSR Configuration to Create
        vgws_create = vpn_gws.get('create')
        # List of VirtualGateways VPNConnections and CSR Configuration to Delete
        vgws_delete = vpn_gws.get('delete')

        delete_customer_gateways = False

        # Create VPNConnections for Spoke VPC tagged to create
        if vgws_create and len(vgws_create) > 0:
            cg1, cg2 = customerGateways(config, ec2, 'create')
            for vgw in vgws_create:
                createVirtualGatewayVpn(account_id, ec2, s3, cg1, cg2, config,
                                        vgws_create.get(vgw))
        else:
            delete_customer_gateways = True

        # Delete VPNConnections for Spoke VPC tagget to delete
        if vgws_delete and len(vgws_delete) > 0:
            for vgw in vgws_delete:
                deleteVirtualGatewayVpn(account_id, ec2, s3, config,
                                        vgws_delete.get(vgw))

        # Delete CustomerGateways if no spoke VPC is tagged to create
        if delete_customer_gateways:
            customerGateways(config, ec2, 'delete')

        log.info('Checked region: %s', region)
