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
import paramiko
import json
import ast
import time
import os
import string
import logging

log = logging.getLogger()
log.setLevel(logging.INFO)

config_file = 'transit_vpc_config.txt'
# These S3 endpoint URLs are provided to support VPC endpoints for S3 in
# regions such as Frankfort that require explicit region endpoint
# definition
endpoint_url = {
    "us-east-1": "https://s3.amazonaws.com",
    "us-east-2": "https://s3-us-east-2.amazonaws.com",
    "us-west-1": "https://s3-us-west-1.amazonaws.com",
    "us-west-2": "https://s3-us-west-2.amazonaws.com",
    "eu-west-1": "https://s3-eu-west-1.amazonaws.com",
    "eu-central-1": "https://s3-eu-central-1.amazonaws.com",
    "ap-northeast-1": "https://s3-ap-northeast-1.amazonaws.com",
    "ap-northeast-2": "https://s3-ap-northeast-2.amazonaws.com",
    "ap-south-1": "https://s3-ap-south-1.amazonaws.com",
    "ap-southeast-1": "https://s3-ap-southeast-1.amazonaws.com",
    "ap-southeast-2": "https://s3-ap-southeast-2.amazonaws.com",
    "sa-east-1": "https://s3-sa-east-1.amazonaws.com"
}


# Logic to determine when the prompt has been discovered
def prompt(chan):
    buff = ''
    while not buff.endswith('#'):
        resp = chan.recv(9999)
        buff += resp
        # log.debug("%s",resp)
    return buff


# Logic to figure out the next availble tunnel
def getNextTunnelId(ssh):
    log.debug('Start getNextTunnelId')
    ssh.send('term len 0\n')
    log.debug("%s", prompt(ssh))
    ssh.send('config t\n')
    log.debug("%s", prompt(ssh))
    ssh.send('do show int summary | include Tunnel\n')
    output = prompt(ssh)
    log.debug("%s", output)
    ssh.send('exit\n')
    log.debug("%s", prompt(ssh))
    lastTunnelNum = ''
    for line in output.split('\n'):
        line = line.replace('* Tunnel', 'Tunnel')
        log.debug("%s", line)
        if line.strip()[:6] == 'Tunnel':
            lastTunnelNum = line.strip().partition(' ')[0].replace('Tunnel',
                                                                   '')

    if lastTunnelNum == '':
        return 1
    return int(lastTunnelNum) + 1


# Logic to figure out existing tunnel IDs
def getExistingTunnelId(ssh, vpn_connection_id):
    log.debug('Start getExistingTunnelId')
    ssh.send('term len 0\n')
    log.debug("%s", prompt(ssh))
    #ssh.send('config t\n')
    # log.debug("%s",prompt(ssh))
    # Display keyrings so we can derive tunnelId
    ssh.send('show run | include crypto keyring\n')
    output = prompt(ssh)
    log.debug("%s", output)
    tunnelNum = 0
    # Now parse crypto keyring lines for keyring-vpn-connection_id-tunnelId
    for line in output.split('\n'):
        if vpn_connection_id in line:
            tmpNum = int(line.split('-')[-1])
            if tunnelNum < tmpNum:
                tunnelNum = tmpNum

    if tunnelNum == 0:
        log.error('Unable to find existing tunnels for %s', vpn_connection_id)
        return 0
    # Parsing logic gets the greater of the two tunnel numbers, so return
    # tunnelNum -1 to get the first tunnel number
    return tunnelNum - 1


# Generic logic to push pre-generated Cisco config to the router
def pushConfig(ssh, config):
    #log.info("Starting to push config")
    #ssh.send('term len 0\n')
    # prompt(ssh)
    ssh.send('config t\n')
    log.debug("%s", prompt(ssh))
    stime = time.time()
    for line in config:
        if line == "WAIT":
            log.debug("Waiting 30 seconds...")
            time.sleep(30)
        else:
            ssh.send(line + '\n')
            log.debug("%s", prompt(ssh))
    ssh.send('exit\n')
    log.debug("%s", prompt(ssh))
    log.debug("   --- %s seconds ---", (time.time() - stime))
    log.info("Saving config!")
    ssh.send('copy run start\n\n\n\n\n')
    log.info("%s", prompt(ssh))
    log.info("Update complete!")


# Logic to determine the bucket prefix from the S3 key name that was provided
def getBucketPrefix(bucket_name, bucket_key):
    # Figure out prefix from known bucket_name and bucket_key
    bucket_prefix = '/'.join(bucket_key.split('/')[:-2])
    if len(bucket_prefix) > 0:
        bucket_prefix += '/'
    return bucket_prefix


# Logic to download the transit VPC configuration file from S3
def getTransitConfig(region, bucket_name, bucket_prefix, s3_url, config_file):
    s3 = boto3.client(
        's3',
        endpoint_url=s3_url,
        region_name=region,
        config=Config(
            s3={'addressing_style': 'virtual'}, signature_version='s3v4'))
    log.info("Downloading config file: %s/%s/%s%s", s3_url, bucket_name,
             bucket_prefix, config_file)
    return ast.literal_eval(
        s3.get_object(Bucket=bucket_name, Key=bucket_prefix + config_file)[
            'Body'].read())


# Logic to upload a new/updated transit VPC configuration file to S3 (not currently used)
def putTransitConfig(region, bucket_name, bucket_prefix, s3_url, config_file,
                     config):
    s3 = boto3.client(
        's3',
        endpoint_url=s3_url,
        region_name=region,
        config=Config(
            s3={'addressing_style': 'virtual'}, signature_version='s3v4'))
    log.info("Uploading new config file: %s/%s/%s%s", s3_url, bucket_name,
             bucket_prefix, config_file)
    s3.put_object(
        Bucket=bucket_name, Key=bucket_prefix + config_file, Body=str(config))


# Logic to download the SSH private key from S3 to be used for SSH public key authentication
def downloadPrivateKey(region, bucket_name, bucket_prefix, s3_url, prikey):
    if os.path.exists('/tmp/' + prikey):
        os.remove('/tmp/' + prikey)
    s3 = boto3.client(
        's3',
        endpoint_url=s3_url,
        region_name=region,
        config=Config(
            s3={'addressing_style': 'virtual'}, signature_version='s3v4'))
    log.info("Downloading private key: %s/%s/%s%s", s3_url, bucket_name,
             bucket_prefix, prikey)
    s3.download_file(bucket_name, bucket_prefix + prikey, '/tmp/' + prikey)


# Logic to create the appropriate Cisco configuration
def create_cisco_config(region, bucket_name, bucket_key, s3_url, bgp_asn, ssh):
    log.info("Processing %s/%s", bucket_name, bucket_key)

    # Download the VPN configuration XML document
    s3 = boto3.client(
        's3',
        endpoint_url=s3_url,
        region_name=region,
        config=Config(
            s3={'addressing_style': 'virtual'}, signature_version='s3v4'))
    config = s3.get_object(Bucket=bucket_name, Key=bucket_key)

    json_config = json.loads(config['Body'].read())
    # Return empty list if configuration attribute is not found
    if not json_config:
        return []

    ipsec_tunnels = json_config.get('ipsec_tunnels')
    vpn_connection_id = json_config.get('vpn_connection_id')
    transit_vpc_config = json_config.get('transit_vpc_config')

    # Extract ['transit_vpc_config'] attributes
    account_id = transit_vpc_config.get('account_id')
    vpn_endpoint = transit_vpc_config.get('vpn_endpoint')
    vpn_status = transit_vpc_config.get('status')
    preferred_path = transit_vpc_config.get('preferred_path')
    planets = transit_vpc_config.get('planet')
    region = transit_vpc_config.get('region')
    customer_gateway_id = transit_vpc_config.get('cgw-3e799057')
    vpn_gateway_id = transit_vpc_config.get('vgw-23a74f4a')
    vpn_connection_type = transit_vpc_config.get('ipsec.1')

    # Determine the VPN tunnels to work with
    if vpn_status == 'create':
        tunnelId = getNextTunnelId(ssh)
    else:
        tunnelId = getExistingTunnelId(ssh, vpn_connection_id)
        if tunnelId == 0:
            return

    log.info("%s %s with tunnel #%s and #%s.", vpn_status, vpn_connection_id,
             tunnelId, tunnelId + 1)
    # Create or delete the VRF for this connection
    if vpn_status == 'delete':
        ipsec_tunnel = ipsec_tunnels[0]
        customer_gateway = ipsec_tunnel.get('customer_gateway')
        customer_gateway_bgp_asn = customer_gateway.get('bgp').get('asn')
        # Remove VPN configuration for both tunnels
        config_text = ['router bgp {}'.format(customer_gateway_bgp_asn)]
        config_text.append(
            '  no address-family ipv4 vrf {}'.format(vpn_connection_id))
        config_text.append('exit')
        config_text.append('no ip vrf {}'.format(vpn_connection_id))
        config_text.append('interface Tunnel{}'.format(tunnelId))
        config_text.append('  shutdown')
        config_text.append('exit')
        config_text.append('no interface Tunnel{}'.format(tunnelId))
        config_text.append('interface Tunnel{}'.format(tunnelId + 1))
        config_text.append('  shutdown')
        config_text.append('exit')
        config_text.append('no interface Tunnel{}'.format(tunnelId + 1))
        config_text.append(
            'no route-map rm-{} permit'.format(vpn_connection_id))
        # Cisco requires waiting 60 seconds before removing the isakmp profile
        config_text.append('WAIT')
        config_text.append('WAIT')
        config_text.append('no crypto isakmp profile isakmp-{}-{}'.format(
            vpn_connection_id, tunnelId))
        config_text.append('no crypto isakmp profile isakmp-{}-{}'.format(
            vpn_connection_id, tunnelId + 1))
        config_text.append('no crypto keyring keyring-{}-{}'.format(
            vpn_connection_id, tunnelId))
        config_text.append('no crypto keyring keyring-{}-{}'.format(
            vpn_connection_id, tunnelId + 1))
    else:
        # Create global tunnel configuration
        config_text = ['ip vrf {}'.format(vpn_connection_id)]
        config_text.append(' rd {}:{}'.format(bgp_asn, tunnelId))
        config_text.append(' route-target export {}:0'.format(bgp_asn))
        config_text.append(' route-target import {}:0'.format(bgp_asn))
        config_text.append('exit')
        # Check to see if a route map is needed for creating a preferred path
        if preferred_path != 'none':
            config_text.append(
                'route-map rm-{} permit'.format(vpn_connection_id))
            # If the preferred path is this transit VPC vpn endpoint, then set
            # a shorter as-path prepend than if it is not
            if preferred_path == vpn_endpoint:
                config_text.append('  set as-path prepend {}'.format(bgp_asn))
            else:
                config_text.append(
                    '  set as-path prepend {} {}'.format(bgp_asn, bgp_asn))
            config_text.append('exit')

        # Create tunnel specific configuration
        for ipsec_tunnel in ipsec_tunnels:
            customer_gateway = ipsec_tunnel.get('customer_gateway')
            customer_gateway_tunnel_outside_address = customer_gateway.get(
                'tunnel_outside_address').get('ip_address')
            customer_gateway_tunnel_inside_address_ip_address = customer_gateway.get(
                'tunnel_inside_address').get('ip_address')
            customer_gateway_tunnel_inside_address_network_mask = customer_gateway.get(
                'tunnel_inside_address').get('network_mask')
            customer_gateway_tunnel_inside_address_network_cidr = customer_gateway.get(
                'tunnel_inside_address').get('network_cidr')
            customer_gateway_bgp_asn = customer_gateway.get('bgp').get('asn')
            customer_gateway_bgp_hold_time = customer_gateway.get('bgp').get(
                'hold_time')

            vpn_gateway = ipsec_tunnel.get('vpn_gateway')
            vpn_gateway_tunnel_outside_address = vpn_gateway.get(
                'tunnel_outside_address').get('ip_address')
            vpn_gateway_tunnel_inside_address_ip_address = vpn_gateway.get(
                'tunnel_inside_address').get('ip_address')
            vpn_gateway_tunnel_inside_address_network_mask = vpn_gateway.get(
                'tunnel_inside_address').get('network_mask')
            vpn_gateway_tunnel_inside_address_network_cidr = vpn_gateway.get(
                'tunnel_inside_address').get('network_cidr')
            vpn_gateway_bgp_asn = vpn_gateway.get('bgp').get('asn')
            vpn_gateway_bgp_hold_time = vpn_gateway.get('bgp').get('hold_time')

            ike = ipsec_tunnel.get('ike')
            ike_authentication_protocol = ike.get('authentication_protocol')
            ike_encryption_protocol = ike.get('encryption_protocol')
            ike_lifetime = ike.get('lifetime')
            ike_perfect_forward_secrecy = ike.get('perfect_forward_secrecy')
            ike_mode = ike.get('mode')
            ike_pre_shared_key = ike.get('pre_shared_key')

            ipsec = ipsec_tunnel.get('ipsec')
            ipsec_protocol = ipsec.get('protocol')
            ipsec_authentication_protocol = ipsec.get(
                'authentication_protocol')
            ipsec_encryption_protocol = ipsec.get('encryption_protocol')
            ipsec_lifetime = ipsec.get('lifetime')
            ipsec_perfect_forward_secrecy = ipsec.get(
                'perfect_forward_secrecy')
            ipsec_mode = ipsec.get('mode')
            ipsec_clear_df_bit = ipsec.get('clear_df_bit')
            ipsec_fragmentation_before_encryption = ipsec.get(
                'fragmentation_before_encryption')
            ipsec_tcp_mss_adjustment = ipsec.get('tcp_mss_adjustment')
            ipsec_dead_peer_detection_interval = ipsec.get(
                'dead_peer_detection').get('interval')
            ipsec_dead_peer_detection_retries = ipsec.get(
                'dead_peer_detection').get('retries')

            config_text.append('crypto keyring keyring-{}-{}'.format(
                vpn_connection_id, tunnelId))
            config_text.append('  local-address GigabitEthernet1')
            config_text.append('  pre-shared-key address {} key {}'.format(
                vpn_gateway_tunnel_outside_address, ike_pre_shared_key))
            config_text.append('exit')
            config_text.append('crypto isakmp profile isakmp-{}-{}'.format(
                vpn_connection_id, tunnelId))
            config_text.append('  local-address GigabitEthernet1')
            config_text.append('  match identity address {}'.format(
                vpn_gateway_tunnel_outside_address))
            config_text.append(
                '  keyring keyring-{}-{}'.format(vpn_connection_id, tunnelId))
            config_text.append('exit')
            config_text.append('interface Tunnel{}'.format(tunnelId))
            config_text.append(
                '  ip vrf forwarding {}'.format(vpn_connection_id))
            config_text.append('  ip address {} 255.255.255.252'.format(
                customer_gateway_tunnel_inside_address_ip_address))
            config_text.append('  ip virtual-reassembly')
            config_text.append('  tunnel source GigabitEthernet1')
            config_text.append('  tunnel destination {} '.format(
                vpn_gateway_tunnel_outside_address))
            config_text.append('  tunnel mode ipsec ipv4')
            config_text.append(
                '  tunnel protection ipsec profile ipsec-vpn-aws')
            config_text.append('  ip tcp adjust-mss 1387')
            config_text.append('  no shutdown')
            config_text.append('exit')
            config_text.append(
                'router bgp {}'.format(customer_gateway_bgp_asn))
            config_text.append(
                '  address-family ipv4 vrf {}'.format(vpn_connection_id))
            config_text.append('  neighbor {} remote-as {}'.format(
                vpn_gateway_tunnel_inside_address_ip_address,
                vpn_gateway_bgp_asn))
            if preferred_path != 'none':
                config_text.append('  neighbor {} route-map rm-{} out'.format(
                    vpn_gateway_tunnel_inside_address_ip_address,
                    vpn_connection_id))
            config_text.append('  neighbor {} timers 10 30 30'.format(
                vpn_gateway_tunnel_inside_address_ip_address))
            config_text.append('  neighbor {} activate'.format(
                vpn_gateway_tunnel_inside_address_ip_address))
            config_text.append('  neighbor {} as-override'.format(
                vpn_gateway_tunnel_inside_address_ip_address))
            config_text.append(
                '  neighbor {} soft-reconfiguration inbound'.format(
                    vpn_gateway_tunnel_inside_address_ip_address))
            config_text.append('exit')
            config_text.append('exit')

            # Increment tunnel ID for going onto the next tunnel
            tunnelId += 1

    log.debug("Conversion complete")
    return config_text


def lambda_handler(event, context):
    record = event['Records'][0]
    bucket_name = record['s3']['bucket']['name']
    bucket_key = record['s3']['object']['key']
    bucket_region = record['awsRegion']
    bucket_prefix = getBucketPrefix(bucket_name, bucket_key)
    log.debug("Getting config")
    stime = time.time()

    config = getTransitConfig(bucket_region, bucket_name, bucket_prefix,
                              endpoint_url[bucket_region], config_file)

    csr_access_ip_type = config.get('CSR_ACCESS_IP_TYPE') or 'private'

    if 'CSR1' in bucket_key:
        csr_name = 'CSR1'
        if csr_access_ip_type == 'public':
            csr_ip = config['EIP1']
        else:
            csr_ip = config['PIP1']
    else:
        csr_name = 'CSR2'
        if csr_access_ip_type == 'public':
            csr_ip = config['EIP2']
        else:
            csr_ip = config['PIP2']

    log.info("--- %s seconds ---", (time.time() - stime))
    # Download private key file from secure S3 bucket
    downloadPrivateKey(bucket_region, bucket_name, bucket_prefix,
                       endpoint_url[bucket_region], config['PRIVATE_KEY'])
    log.debug("Reading downloaded private key into memory.")
    k = paramiko.RSAKey.from_private_key_file("/tmp/" + config['PRIVATE_KEY'])
    # Delete the temp copy of the private key
    os.remove("/tmp/" + config['PRIVATE_KEY'])
    log.debug("Deleted downloaded private key.")

    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    log.info("Connecting to %s (%s)", csr_name, csr_ip)
    stime = time.time()
    try:
        c.connect(hostname=csr_ip, username=config['USER_NAME'], pkey=k)
        PubKeyAuth = True
    except paramiko.ssh_exception.AuthenticationException:
        log.error("PubKey Authentication Failed! Connecting with password")
        c.connect(
            hostname=csr_ip,
            username=config['USER_NAME'],
            password=config['PASSWORD'])
        PubKeyAuth = False
    log.info("--- %s seconds ---", (time.time() - stime))
    log.debug("Connected to %s", csr_ip)
    ssh = c.invoke_shell()
    log.debug("%s", prompt(ssh))
    log.debug("Creating config.")
    stime = time.time()
    csr_config = create_cisco_config(bucket_region, bucket_name, bucket_key,
                                     endpoint_url[bucket_region],
                                     config['BGP_ASN'], ssh)
    log.info("--- %s seconds ---", (time.time() - stime))
    log.info("Pushing config to router.")
    stime = time.time()
    pushConfig(ssh, csr_config)
    log.info("--- %s seconds ---", (time.time() - stime))
    ssh.close()

    return
    {
        'message':
        "Script execution completed. See Cloudwatch logs for complete output"
    }
