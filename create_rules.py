#!/usr/bin/python3
import sys

import requests
import json
import random
import argparse
import ipaddress
from typing import Dict
from typing import Tuple

def is_valid_ipv4_cidr(ip_with_cidr: str) -> bool:
    """
    Verifies if a string is a valid IPv4 subnet in CIDR notation (x.x.x.x/y).

    Parameters:
    ip_with_cidr (str): The string potentially representing an IPv4 subnet.

    Returns:
    bool: True if the string is a valid IPv4 subnet in CIDR notation, False otherwise.
    """

    # 'ipaddress.IPv4Network' function is used to create an IPv4 network object.
    # If the provided string is not a valid IPv4 subnet, a ValueError exception is raised.
    try:
        ipaddress.IPv4Network(ip_with_cidr)
        return True
    except ValueError:
        return False

def read_file(file_path: str) -> list:
    """
    Reads a list of strings from a .txt file, one string per line.

    Parameters:
    file_path (str): The path to the file to be read;

    Returns:
    str_list (list): A list of strings.
    """
    try:
        with open(file_path, 'r') as file:
            str_list = [line.strip() for line in file if is_valid_ipv4_cidr(line.strip())]
            return str_list
    except Exception as ex:
        print(f"Error: File {file_path}: {ex}")
        sys.exit(-1)

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

    subnet_list = read_file(args.file)
    address_groups.append({
        "group-name": "trex_net",
        "address-types": {
            "ip-subnets": [
                subnet_list

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

def create_trex_sec(user_pass: Tuple[str, str], headers: Dict[str, str], context: str, size: int, server: str,
                    port: str) -> None:

    """
    Creates a security policy ('sec') for a given context with prepopulated 'Trex' rules.

    This function configures a  security policy on the controlled firewall with the default
    action of accepting packets coming from specified 'Trex' source networks.

    Parameters:
    user_pass (Tuple[str, str]): a tuple that contains the username and password for authentication;
    headers (Dict[str, str]): a dictionary with HTTP headers for the request;
    context (str): the context in which it is necessary to create the SEC entries;
    size (int): size of the SEC entries list;
    server (str): The IP address of the RESTCONF server;
    port (str): The listening port of the RESTCONF server;

    Returns:
    None. The function sends a PUT request to the server with the required sec policy structure
    and displays the HTTP response code and message in the console.

    Note:
    The hardcoded 'Trex' rules are made to facilitate the developer team avoiding manual rule creation.
    """

    print(f"Generate SEC...")
    sec_entries_list = []

    # это для того что бы руками не создавать правила для тирекса (только для команды разработки)
    sec_entry = {
        "sequence-id": size + 5,
        "enabled": "true",
        "actions": {
            "config": {
                "forwarding-action": "accept"
            }
        },
        "src-address": [
            "trex_net"
        ]
    }
    sec_entries_list.append(sec_entry)

    access_policy = {
        "clixon-ngfw:security-policies-ipv4": {
            "security-policy": {
                "type": "sec_ipv4",
                "sec-entries": {
                    "sec-entry": sec_entries_list
                }
            }
        }
    }

    response = requests.put(
        f'http://{server}:{port}/restconf/data/clixon-ngfw:contexts/context={context}/firewall/security-policies-ipv4',
        headers=headers, data=json.dumps(access_policy), auth=user_pass)
    if response.text:
        print(f"Result for add SEC policy: {response.status_code} {response.text}\n")
    else:
        print(f"Result for add SEC policy: {response.status_code}\n")

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
    parser.add_argument('-f', '--file', type=str, required=True,
                        help='Path to the file with subnets. This argument is required.')
    return parser.parse_args()

# Example: create_rules.py -s [num_rules] -c [context_name] -S [server_ip] -p [server_port] -f [file_with_subnets]
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
    create_trex_sec(user_pass, headers, args.context, args.size, args.server, args.port)
