## Firewall Script with Access Control Lists (ACLs)

This script is designed to create and handle Access Control Lists (ACLs) 
for a firewall on a given context.

It is equipped with the functionality to delete all firewall nodes, to 
create random subnets with groups and to create ACL entries with an 
accepting action which are added to access policy. Moreover, it can 
create a security policy with prepopulated 'User' rules.

### Getting started

You must have Python3 installed on your machine.

You also need the following Python packages which can be installed using pip:
````
pip install -r requirements.txt
````

### Usage:

To run the script, you need to use a terminal/cmd. Navigate to the directory 
containing the script. Now you can run the script using Python.
````
$ create_rules.py -s [num_rules] -c [context_name] -S [server_ip] -p [server_port]
````
### Options:

* -s [num_rules] or --size [num_rules]: The number of rules to be created. 
This argument is required.
* -c [context_name] or --context [context_name]: The name of the context 
that the rules are interacting with. This argument is required.
* -S [server_ip] or --server [server_ip]: The IP address of the RESTCONF 
server. This argument is required.
* -p [server_port] or --port [server_port]: The listening port of the 
RESTCONF server. This argument is required.

### Script content:

**The script includes several functions:**
* delete_node_firewall: this function deletes all nodes of the firewall.
* create_subnets: this function creates randomly generated subnets for a given context.
* create_acl: this function creates ACL entries with an accepting action for a given context.
* create_sec: this function creates a security policy with prepopulated 'User' rules for a given context.

### Disclaimer

**_Remember to replace the credentials ('user_pass') depending on the environment you're working with before using the script._**