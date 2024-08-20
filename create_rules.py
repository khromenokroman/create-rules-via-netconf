#!/usr/bin/python3
import requests
import json
import random
import argparse
from typing import Dict
from typing import Tuple


def delete_node_firewall(user_pass: Tuple[str, str], headers: Dict[str, str], context: str, server: str,
                   port: str) -> None:
    """
    Function for deleting all node firewall.

    Parameters:
    user_pass (Tuple[str, str]): tuple containing the username and password for authentication;
    headers (Dict[str, str]): dictionary with HTTP headers for the request;
    context (str): the context in which you need to delete node firewall.
    server (str): restconf server.
    port (str): restconf port.

    Returns:
    None. The function makes a DELETE request to the server and prints the result to the console.
    """

    print("Delete node firewall...")
    url = f'http://{server}:{port}/restconf/data/clixon-ngfw:contexts/context={context}/firewall'
    response = requests.delete(url, headers=headers, auth=user_pass)
    if response.text:
        print(f"Result for delete node firewall: {response.status_code} {response.text}\n")
    else:
        print(f"Result for delete node firewall: {response.status_code}\n")


def create_trex_subnets(user_pass: Tuple[str, str], headers: Dict[str, str], context: str, size: int, server: str,
                        port: str) -> None:
    """
    Creates groups of randomly generated subnets for a given context.

    Parameters:
    user_pass (Tuple[str, str]): a tuple that contains the username and password for authentication;
    headers (Dict[str, str]): a dictionary with HTTP headers for the request;
    context (str): the context in which the subnets need to be created;
    size (int): the number of subnets that need to be created.
    server (str): restconf server.
    port (str): restconf port.

    Returns:
    None. The function sends a PUT request to the server and displays the result in the console.
    """

    print(f"Generate subnets...")
    address_groups = []

    for i in range(1, size + 1):
        octet_1 = random.randint(1, 255)
        octet_2 = random.randint(1, 255)
        octet_3 = random.randint(1, 255)
        octet_4 = random.randint(1, 255)

        ip = f"{octet_1}.{octet_2}.{octet_3}.{octet_4}"
        name = f"group-{i}"

        address_groups.append({
            "group-name": name,
            "address-types": {
                "ip-subnets": [
                    f"{ip}/32"
                ]
            }
        })

    # это для того что бы руками не создавать правила для тирекса (только для команды разработки)
    address_groups.append({
        "group-name": "trex_net",
        "address-types": {
            "ip-subnets": [
                "10.1.0.0/16",
                "10.2.0.0/16",
                "10.3.0.0/16",
                "10.4.0.0/16",
                "10.5.0.0/16",
                "10.6.0.0/16",
                "10.7.0.0/16",
                "10.8.0.0/16"
            ]
        }
    })

    data = {
        "clixon-ngfw:ipv4-address": {
            "address-group": address_groups
        }
    }

    response = requests.put(
        f'http://{server}:{port}/restconf/data/clixon-ngfw:contexts/context={context}/firewall/address/ipv4/ipv4-address',
        headers=headers, data=json.dumps(data), auth=user_pass)
    if response.text:
        print(f"Result for add subnets: {response.status_code} {response.text}\n")
    else:
        print(f"Result for add subnets: {response.status_code}\n")


def create_trex_acl(user_pass: Tuple[str, str], headers: Dict[str, str], context: str, size: int, server: str,
                    port: str) -> None:
    """
    Creates the specified number of Access Control List (ACL) entries with
    the accepting action and adds them to the access policy.

    Parameters:
    user_pass (Tuple[str, str]): a tuple that contains the username and password for authentication;
    headers (Dict[str, str]): a dictionary with HTTP headers for the request;
    context (str): the context in which it is necessary to create ACL entries;
    size (int): the number of ACL entries to be created.
    server (str): restconf server.
    port (str): restconf port.

    Returns:
    None. The function sends a PUT request to the server and displays the result in the console.
    """

    print(f"Generate ACL...")
    acl_entries_list = []

    for i in range(1, size + 1):
        name = f"group-{i}"

        acl_entry = {
            "sequence-id": i,
            "actions": {
                "config": {
                    "forwarding-action": "accept"
                }
            },
            "src-address": [
                name
            ]
        }
        acl_entries_list.append(acl_entry)

    # это для того что бы руками не создавать правила для тирекса (только для команды разработки)
    acl_entry = {
        "sequence-id": size + 5,
        "actions": {
            "config": {
                "forwarding-action": "accept"
            }
        },
        "src-address": [
            "trex_net"
        ]
    }
    acl_entries_list.append(acl_entry)

    access_policy = {
        "clixon-ngfw:access-policies-ipv4": {
            "access-policy": {
                "type": "acl_ipv4",
                "config": {
                    "name": "def_drop",
                    "default-policy": "drop"
                },
                "acl-entries": {
                    "acl-entry": acl_entries_list
                }
            }
        }
    }

    response = requests.put(
        f'http://{server}:{port}/restconf/data/clixon-ngfw:contexts/context={context}/firewall/access-policies-ipv4',
        headers=headers, data=json.dumps(access_policy), auth=user_pass)
    if response.text:
        print(f"Result for add subnets: {response.status_code} {response.text}\n")
    else:
        print(f"Result for add subnets: {response.status_code}\n")


def parse_arguments():
    parser = argparse.ArgumentParser(description='Script for generating Access Control Lists (ACLs)')
    parser.add_argument('-s', '--size', type=int, required=True,
                        help='The number of rules being created. This argument is required.')
    parser.add_argument('-c', '--context', type=str, required=True,
                        help='The name of the context that we are editing. This argument is required.')
    parser.add_argument('-S', '--server', type=str, required=True,
                        help='IP address restconf server. This argument is required.')
    parser.add_argument('-p', '--port', type=str, required=True,
                        help='Port restconf server. This argument is required.')
    return parser.parse_args()


if __name__ == '__main__':
    args = parse_arguments()
    user_pass = ('sysadmin',
                 '$6$Edxj1MHJOWWrst2D$YTkLzv7EFQrSKeYWTq7BSw0Bu33qq5Teo/G.fMs2w0IcY0wwmLB25qVxa6/hHrSMhQvBrrfjaYIJ85d9D6zkj/')
    headers = {
        'Content-Type': 'application/yang-data+json',
    }

    delete_node_firewall(user_pass, headers, args.context, args.server, args.port)
    create_trex_subnets(user_pass, headers, args.context, args.size, args.server, args.port)
    create_trex_acl(user_pass, headers, args.context, args.size, args.server, args.port)
