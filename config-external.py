#! /usr/bin/python

'''
 Copyright 2019-present SK Telecom
 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at
     http://www.apache.org/licenses/LICENSE-2.0
 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
'''

import os
import shlex
import sys
import traceback
import time
import json
import pyroute2
import ConfigParser
import socket
import struct
import netifaces
# from netaddr import *
from kubernetes import client, config

SONA_CONFIG_FILE = "/etc/sona/sona-cni.conf"
SONA_CONFIG_FILE_ENV = os.environ.get("SONA_CONFIG_FILE_PATH")
EXTERNAL_GW_IP = "external.gateway.ip"
EXTERNAL_INTF_NAME = "external.interface.name"
EXTERNAL_BR_IP = "external.bridge.ip"
# SONA Mod
EXTERNAL_OVS_IP = "external.ovs.ip"
EXTERNAL_OVS_INTF = "external.ovs.interface.name"
MGMT_INTF_IP = "management.interface.ip"

def get_external_interface():
    '''
    Obtains the external interface name.

    :return     external interface name
    '''
    try:
        sona_config_file = SONA_CONFIG_FILE
        if SONA_CONFIG_FILE_ENV is not None:
            sona_config_file = SONA_CONFIG_FILE_ENV

        cf = ConfigParser.ConfigParser()
        cf.read(sona_config_file)
        if cf.has_option("network", "external_interface") is True:
            return cf.get("network", "external_interface")
        else:
            return None

    except Exception as e:
        raise SonaException(102, "failure get external interface " + str(e))

def get_external_ovs_interface():
    '''
    Obtains the external OvS interface name.

    :return     external OvS interface name
    '''
    try:
        sona_config_file = SONA_CONFIG_FILE
        if SONA_CONFIG_FILE_ENV is not None:
            sona_config_file = SONA_CONFIG_FILE_ENV

        cf = ConfigParser.ConfigParser()
        cf.read(sona_config_file)
        if cf.has_option("network", "external_ovs_interface") is True:
            return cf.get("network", "external_ovs_interface")
        else:
            return None

    except Exception as e:
        raise SonaException(102, "failure get external OvS interface " + str(e))

def get_management_interface():
    '''
    Obtains the management interface name. (For OvSDB and ONOS to OvS connectivity)

    :return     management interface name
    '''
    try:
        sona_config_file = SONA_CONFIG_FILE
        if SONA_CONFIG_FILE_ENV is not None:
            sona_config_file = SONA_CONFIG_FILE_ENV

        cf = ConfigParser.ConfigParser()
        cf.read(sona_config_file)
        if cf.has_option("network", "management_interace") is True:
            return cf.get("network", "management_interace")
        else:
            return None

    except Exception as e:
        raise SonaException(102, "failure get management interface " + str(e))

def get_management_interface_ip():
    '''
    Get interface IP address of management interface on current node.

    :return management int IP address
    '''
    try:
        ipdb = pyroute2.IPDB(mode='explicit')
        mgmt_int_name = get_management_interface()
        addr = ipdb.interfaces[mgmt_int_name].ipaddr[0]
        mgmt_int_ip = addr[0] # Get first element of tuple, https://docs.pyroute2.org/ipdb.html#ip-address-management
        return mgmt_int_ip

    except Exception as e:
        print(traceback.format_exc())
        raise SonaException(102, "failure get management interface ip " + str(e))

def get_external_bridge_ip():
    '''
    Obtains the external IP address.
    
    :return	external IP address
    '''
    ext_interface = get_external_interface()
    return netifaces.ifaddresses(ext_interface)[netifaces.AF_INET][0]['addr']

def get_external_gateway_ip():
    '''
    Obtains the external gateway IP address.

    :return    external gateway IP address
    '''
    try:
        sona_config_file = SONA_CONFIG_FILE
        if SONA_CONFIG_FILE_ENV is not None:
            sona_config_file = SONA_CONFIG_FILE_ENV

        cf = ConfigParser.ConfigParser()
        cf.read(sona_config_file)
        if cf.has_option("network", "external_gateway_ip") is True:
            return cf.get("network", "external_gateway_ip")
        else:
            return None

    except Exception as e:
        raise SonaException(102, "failure get external gateway IP " + str(e))

def get_external_ovs_ip():
    '''
    Obtains the external OvS IP address.

    :return    external OvS IP address
    '''
    try:
        sona_config_file = SONA_CONFIG_FILE
        if SONA_CONFIG_FILE_ENV is not None:
            sona_config_file = SONA_CONFIG_FILE_ENV

        cf = ConfigParser.ConfigParser()
        cf.read(sona_config_file)
        if cf.has_option("network", "external_ovs_ip") is True:
            return cf.get("network", "external_ovs_ip")
        else:
            return None

    except Exception as e:
        raise SonaException(102, "failure get external OvS IP " + str(e))

def is_interface_up(interface):
    '''
    Checks whether the given network interface is up or not.
    '''
    addr = netifaces.ifaddresses(interface)
    return netifaces.AF_INET in addr

def addAnnotationToNode(api_instance, node_name, annot_key, annot_value):
    '''
    Adds annotaion to the existing kubernetes node.
    
    :return	kubernetes node update result
    '''
    node = api_instance.read_node(name=node_name)
    node.metadata.annotations[annot_key] = annot_value
    return api_instance.patch_node(name=node_name, body=node)

def main():

    ex_gw_ip = get_external_gateway_ip()
    ex_br_ip = get_external_bridge_ip()
    ex_gw_intf = get_external_interface()
    ex_ovs_ip = get_external_ovs_ip()
    ex_ovs_intf = get_external_ovs_interface()
    hostname = socket.gethostname()
    management_ip = get_management_interface_ip()

    # Configs can be set in Configuration class directly or using helper utility
    config.load_kube_config()

    v1 = client.CoreV1Api()
 
    if hostname is not None:
        # add external gateway IP address
        addAnnotationToNode(v1, hostname, EXTERNAL_GW_IP, ex_gw_ip)

        # add external interface name
        addAnnotationToNode(v1, hostname, EXTERNAL_INTF_NAME, ex_gw_intf)

        # add external bridge IP
        addAnnotationToNode(v1, hostname, EXTERNAL_BR_IP, ex_br_ip)

        # [Mod] add external OvS IP
        addAnnotationToNode(v1, hostname, EXTERNAL_OVS_IP, ex_ovs_ip)

        # [Mod] add external OvS IP
        addAnnotationToNode(v1, hostname, EXTERNAL_OVS_INTF, ex_ovs_intf)

        # [Mod] add management IP
        addAnnotationToNode(v1, hostname, MGMT_INTF_IP, management_ip)

class SonaException(Exception):

    def __init__(self, code, message, details=None):
        '''
        The exception constructor which handles the SONA related exceptions.

        :param  code:       exception code
                message:    exception message
                details:    detailed message of this exception
        '''
        super(SonaException, self).__init__("%s - %s" % (code, message))
        self._code = code
        self._msg = message
        self._details = details

    def sona_error(self):
        '''
        Handles the SONA related errors.

        :return  exception details including error code and message
        '''
        error_data = {'code': self._code, 'message': self._msg}
        if self._details:
            error_data['details'] = self._details
        return json.dumps(error_data)

if __name__ == '__main__':
    try:
        main()
    except SonaException as e:
        print(e.sona_error())
        sys.exit(1)
    except Exception as e:
        error = {'code': 200, 'message': str(e)}
        print(json.dumps(error))
        sys.exit(1)
