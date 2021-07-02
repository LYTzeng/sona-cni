#!/usr/bin/env python
import os, sys, getopt
# from kubernetes import client, config
import ConfigParser

SONA_CONFIG_FILE = "/etc/sona/sona-cni.conf"
SONA_CONFIG_FILE_ENV = os.environ.get("SONA_CONFIG_FILE_PATH")
ONOS_IP = "controller.ip"

# def master_ip():
#     config.load_kube_config()
#     api_instance = client.CoreV1Api()
#     master_str = "node-role.kubernetes.io/master"
#     node_list = api_instance.list_node()
#     for node in node_list.items:
#         node_labels = node.metadata.labels
#         for labels in node_labels:
#             # TODO: need to check whether the given master node has SONA POD
#             if master_str in labels:
#                 return get_node_address(node)
#     return None
# def get_node_address(node):
#     node_status = node.status
#     for address in node_status.addresses:
#         if address.type == "InternalIP":
#             return address.address
#     return None

def get_controller_ip():
    '''
    Obtains the ONOS controller IP address.

    :return    ONOS controller IP address
    '''

    sona_config_file = SONA_CONFIG_FILE
    if SONA_CONFIG_FILE_ENV is not None:
        sona_config_file = SONA_CONFIG_FILE_ENV

    cf = ConfigParser.ConfigParser()
    cf.read(sona_config_file)
    if cf.has_option("network", "controller_ip") is True:
        return cf.get("network", "controller_ip")
    else:
        return None


def main(argv):
    # print(master_ip())
    print(get_controller_ip())

if __name__ == "__main__":
   main(sys.argv[1:])
