from pprint import pprint
from itertools import izip_longest as izl
from ftntlib import FortiOSREST

import requests
import code
import ConfigParser
import sys
import json
import re
import ipaddress
import pandas as pd
import socket
import code

#TODO: Error handling, clean up comments/code, clean up comments/code again, 
#      speed up results processing, auditing functions, search functions, frontend

class FortiParser:
    """
    Class with functions to connect and parse data from firewalls into pandas
    DataFrames

    Must specify a config file to read from, one [section] for each firewall.
    The section name is used as the top level key in the results dictionary,
    so make it descriptive, i.e. "Border Firewall 1"
    Example:

    [Example Firewall Name]
    ip=123.123.123.123
    username=firewall_service_account
    password=hunter2
    hostname=fqdn.firewall.company.org

    You need to supply either an IP or a hostname, but the config must contain 
    both fields. For whatever field you don't need, just leave it blank or None
    Running this script as is (or main func) will return the class object
    with all the data. Otherwise you can import the module and just grab the stuff
    you need, from vdoms you need
    """

    def __init__(self, config_file=None, custom_fields=None):
        """Init function
        Used to set config file
        Default Args:
        config_file -- Path to config file, will ask for one if none is supplied (default None)
        custom_fields -- Name of section of config containing custom field lists for
                         addresses (and groups), policies, and services (and groups)
                         if None, will use ones supplied below (default None)
                         These are the columns for each DataFrame
                         Note that start and end IP addresses are integers
                         generated with ip2long() so we can search easier
        """

        if not config_file:
            config_file = raw_input("Please input full path to config file: ")
        # TODO Check to make sure necessary fields exist in config file
        if not custom_fields:
            self.address_group_fields = ['firewall',
                                         'vdom',
                                         'comment',
                                         'member',
                                         'name',
                                         'q_origin_key'
                                         'visibility']
            self.address_fields = ['firewall',
                                   'vdom',
                                   'associated-interface',
                                   'comment',
                                   'dns-lookup',
                                   'fqdn',
                                   'name',
                                   'q_origin_key',
                                   'subnet',   #str
                                   'start-ip', #int
                                   'end-ip',   #int
                                   'type',
                                   'url',
                                   'visibility',
                                   'wildcard']
            self.routing_table_fields = ['firewall',
                                         'vdom',
                                         'distance',
                                         'interface',
                                         'ip_mask',
                                         'start-ip',
                                         'end-ip',
                                         'outside_interface',
                                         'type',
                                         'gateway',
                                         'uptime',
                                         'metric']
            self.policy_fields = ['firewall',
                                  'vdom',
                                  'comments',
                                  'dstaddr',
                                  'dstintf',
                                  'logtraffic',
                                  'nat',
                                  'natip',
                                  'policyid',
                                  'order',
                                  'service',
                                  'srcaddr', # List of q_origin_keys
                                  'srcintf',
                                  'status']
            self.service_fields = ['firewall',
                                   'vdom',
                                   'category',
                                   'comment',
                                   'explicit-proxy',
                                   'fqdn',
                                   'icmpcode',
                                   'icmptype',
                                   'iprange',
                                   'name',
                                   'protocol',
                                   'protocol-number',
                                   'q_origin_key',
                                   'sctp-portrange',
                                   'tcp-portrange',
                                   'udp-portrange',
                                   'visibility']
            self.service_group_fields = ['firewall',
                                         'vdom',
                                         'comment',
                                         'explicit-proxy',
                                         'member', #list of q_origin_keys
                                         'name',
                                         'q_origin_key']
            self.config_file = config_file
        #TODO create DataFrames with custom field arg
        self.routing_tables = pd.DataFrame(columns=self.routing_table_fields) # What subnets belong to what interface
        self.policies = pd.DataFrame(columns=self.policy_fields) # All the policies
        self.addresses = pd.DataFrame(columns=self.address_fields) # Includes both addresses and address groups
        self.address_groups = pd.DataFrame(columns=self.address_group_fields)
        self.services = pd.DataFrame(columns=self.service_fields) # Includes both services and service groups
        self.service_groups = pd.DataFrame(columns=self.service_group_fields)
        # Random other stuff we'll use multiple times in IP functions
        self.ipv4cidr_re = ipv4_cidr_re = re.compile('^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/(3[0-2]|[1-2][0-9]|[0-9]))$')
        self.ipv4_re = re.compile('^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$')

    def connect(self, section=None, username=None, password=None, ip=None, hostname=None, debug=False):
        """Connects to a Fortinet firewall using ftntlib
        Can supply creds to the function or read them from a config file
        Must supply at least a section name from the config, or a username and password

        Returns connection object used for REST API commands

        Keyword args:
        username -- account to connect with (default None)
        password -- password to connect with (default None)
        ip       -- IP to connect to (default None)
        hostname -- Hostname to connect to. Only needed if using FQDN to connnect
                    rather than IP (default None)
        section  -- ConfigParser section to read, if not supplying username,
                    password, and IP (default None)
        debug    -- Boolean. If True, will enable debugging output for the session (default False)
        """

        fgtconn = FortiOSREST()
        if debug:
            fgtconn.debug('on')

        # Check to see if creds already supplied, else find them in config by supplied section
        if not username or not password:
            if not section:
                print "Please supply credentials, or specify a section in the config"
                sys.exit()
            else:
                try:
                    # Get info
                    scp = ConfigParser.SafeConfigParser()
                    scp.read(self.config_file)
                    username = scp.get(section, 'username')
                    password = scp.get(section, 'password')
                    ip = scp.get(section, 'ip')
                    hostname = scp.get(section, 'hostname')
                except Exception as e:
                    raise Exception("Could not parse config file.\nError: {}".format(e))

        # Connect
        if ip is not None or ip != "":
            dst = ip
        else:
            dst = hostname
        try:
            fgtconn.login(dst, username, password)
            return fgtconn
        except Exception as e:
            raise Exception("Could not connect to firewall {}.\nError: {}".format(e))

    #######IP ADDRESS FUNCTIONS#######

    def iptolong(self, ip):
        """Converts an IP address (string) to long int
        """
        return int(ipaddress.IPv4Address(u"{}".format(ip)))

    def dnslookup(self, fqdn):
        """Performs DNS lookup on an fqdn and returns the IP address
        Or None if it fails
        """
        try:
            ip = socket.gethostbyname(fqdn)
            longip = self.iptolong(ip)
            return longip
        except Exception as e:
            print "Could not perform dnslookup on {}:\n{}".format(fqdn, e)
            return None

    def convert_subnet(self, subnet):
        """Takes a subnet, either in IP/CIDR or IP NETMASK format, and returns
        the start and end ip in long int form

        Args:
        subnet -- string, the subnet either in IP/cidr or IP NETMASK

        Returns IPv4Network object of the given subnet
        """
        # regex to determine if cidr or netmask
        subnet = subnet.strip().split(' ')
        subnet += [""] * (2-len(subnet))

        # If we have a cidr match
        if self.ipv4cidr_re.match(subnet[0]):
            return ipaddress.IPv4Network(u"{}".format(subnet[0]))
        # or if we have a an "IP Netmask" match
        elif self.ipv4_re.match(subnet[0]) and self.ipv4_re.match(subnet[1]):
            return ipaddress.IPv4Network(subnet[0], subnet[1])
        # Or if we have a single IP address, add a /32
        elif self.ipv4_re.match(subnet[0]) and subnet[1] == "":
            return ipaddress.IPv4Network(u"{}/32".format(subnet[0]))
        else:
            print 'Could not determine IPv4Network for {}'.format(subnet)
            return None

    #######################################


    ####API CALL FUNCTIONS#######


    def get_address_groups(self, fgt, firewall_name, vdom='all', count='-1'):
        """Gets all the address groups from a firewall and adds them to the
        dataframe self.service_groups
        Args:
        fgt -- REST API connection object to a firewall
        firewall_name -- string, the name of the firewall, AKA the section from the config

        Default args:
        vdom -- string, VDOM to parse, or 'all' for all of them (default 'all')
        count -- string, how many results to return, -1 for all (default '-1')
        """
        parameters = {}
        if vdom != 'all':
            parameters['vdom'] = vdom
        else:
            parameters['global'] = '1'
        parameters['count'] = str(count)
        # First lets get address groups

        try:
            results = json.loads(fgt.get('cmdb', 'firewall', 'addrgrp', parameters=parameters).decode('utf-8', "ignore"))
        except Exception as e:
            raise Exception("Could not get address groups: {}".format(e))

        if vdom == 'all':
            for r in results:
                vdom = r['vdom']
                self.address_groups = self.process_results(r, firewall_name, vdom, self.address_groups, self.address_group_fields)
        else:
            self.address_groups = self.process_results(results, firewall_name, vdom, self.address_groups, self.address_group_fields) 

    def get_addresses(self, fgt, firewall_name, vdom='all', count='-1'):
        """Gets all the addresses and address groups from a firewall and adds
        to the dataframe self.addresses

        Args:
        fgt -- REST API connection object to a firewall
        firewall_name -- string of name of firewall AKA section in config
        Default Args:
        vdom -- string, vdom to get address object from (default all)
        count -- string, number of results to return, -1 for all (default -1)
        """
        # Init
        parameters = {}
        if vdom != 'all':
            parameters['vdom'] = vdom
        else:
            parameters['global'] = '1'
        parameters['count'] = str(count)

        try:
            results = json.loads(fgt.get('cmdb', 'firewall', 'address', parameters=parameters).decode('utf-8', "ignore"))
        except Exception as e:
            raise Exception("Could not get addresses: {}".format(e))

        if vdom == 'all':
            for r in results:
                vdom = r['vdom']
                self.addresses = self.process_results(r, firewall_name, vdom, self.addresses, self.addresses)
        else:
            self.addresses = self.process_results(results, firewall_name, vdom, self.addresses, self.address_fields) 

    def get_routing_tables(self, fgt, firewall_name, vdom='all', count='-1'):
        """Gets the routing table from a firewall and convert and converts the 
        ip_mask into a start-ip and end-ip of longints
        puts data into self.routing_tables
        Args:
        fgt -- REST API connection object to a firewall
        firewall_name -- string of firewall name
        Default Args:
        firewall -- String. The firewall to parse the routing table from. If its
                'all', it will parse through all firewalls in the config file.
                (default 'all')
        vdom -- String. The VDOM to return the routing table for. If its 'all', it will
                return anything the account has access to (default all)
        count -- String. The number of results to return, set to '-1' for all (default '-1')
        """
        parameters = {}
        if isinstance(count, int):
            count = str(count)
        if vdom!='all':
            parameters['vdom'] = vdom
        else:
            parameters['global'] = '1'
        parameters['count'] = count
        # Get routing tables
        try:
            results = json.loads(fgt.get('monitor', 'router', 'ipv4', action='select', parameters=parameters))
        except Exception as e:
            raise Exception("Could not get routing table: {}".format(e))
        if vdom == 'all':
            for r in results:
                vdom = r['vdom']
                self.routing_tables = self.process_results(r, firewall_name, vdom, self.routing_tables, self.routing_table_fields, result_type="routing_tables")
                self.routing_tables = self.mark_outside_interfaces(vdom, self.routing_tables)
        else:
            self.routing_tables = self.process_results(results['results'], firewall_name, vdom, self.routing_tables, self.routing_table_fields, result_type="routing_tables")
            self.routing_tables = self.mark_outside_interfaces(vdom, self.routing_tables)


    def get_policies(self, fgt, firewall_name, vdom='all', count='-1'):
        """Gets policies from a firewall, maintains the order by adding an
        'order' column into the self.policies dataframe

        Args:
        fgt - REST API connection to firewall
        firewall_name -- string of name of the firewall
        Default Args:
        vdom - VDOMS to pull policies from (default 'all')
        count - count of policies to pull, -1 for all (default '-1-')
        trim - If True, will trim down policy results to meaningful data (default True)
        fields - Fields to grab if trim=True
        """
        parameters = {}
        if vdom!= 'all':
            parameters['vdom'] = vdom
        else:
            parameters['global'] = '1'
        parameters['count'] = str(count)
        try:
            results = json.loads(fgt.get('cmdb', 'firewall', 'policy', parameters=parameters))
        except Exception as e:
            raise Exception("Could not get policies: {}".format(e))

        if vdom == 'all':
            for r in results:
                vdom = r['vdom']
                self.policies = self.process_results(r, firewall_name, vdom, self.policies, self.policy_fields, result_type="policies")
        else:
            self.policies = self.process_results(results, firewall_name, vdom, self.policies, self.policy_fields, result_type="policies")


    def get_service_groups(self, fgt, firewall_name, vdom='all', count='-1'):
        """Parses service groups from a firewall
        members column is reduced from dictionary of names and q_origin_keys
        to just list of q_origin_keys

        Args:
        fgt -- Connection object to a firewall
        firewall_name -- string of name of firewall
        Default Args:
        vdom -- string, VDOM to grab services from, or all for all vdoms (default 'all')
        count -- string, number of services to return, -1 for all (default -1)
        """

        parameters = {}
        if vdom != 'all':
            parameters[vdom] = vdom
        else:
            parameters['global'] = '1'
        parameters['count'] = count

        # Service groups first
        try:
            results = json.loads(fgt.get('cmdb', 'firewall.service', 'group', parameters=parameters).decode('utf-8', "ignore"))
        except Exception as e:
            raise Exception("Could not parse service groups: {}".format(e))

        if vdom == 'all':
            for r in results:
                vdom = r['vdom']
                self.service_groups = self.process_results(r, firewall_name, vdom, self.service_groups, self.service_group_fields, result_type="services_groups")
        else:
            self.service_groups = self.process_results(results, firewall_name, vdom, self.service_groups, self.service_group_fields, result_type="services_groups")


    def get_services(self, fgt, firewall_name, vdom='all', count='-1'):
        """Parses services from a firewall

        Args:
        fgt -- Connection object to a firewall
        firewall_name -- string of name of firewall

        Default Args:
        vdom -- string, VDOM to grab services from, or all for all vdoms (default 'all')
        count -- string, number of services to return, -1 for all (default -1)
        """
        parameters = {}
        if vdom != 'all':
            parameters[vdom] = vdom
        else:
            parameters['global'] = '1'
        parameters['count'] = count

        # Services
        try:
            results = json.loads(fgt.get('cmdb', 'firewall.service', 'custom', parameters=parameters).decode('utf-8', "ignore"))

        except Exception as e:
            raise Exception("Could not parse services: {}".format(e))

        if vdom == 'all':
            for r in results:
                vdom = r['vdom']
                self.services = self.process_results(r, firewall_name, vdom, self.services, self.service_fields, result_type="services")
        else:
            self.services = self.process_results(results, firewall_name, vdom, self.services, self.service_fields, result_type="services")


    ##### END API CALL FUNCTIONS #####



    def process_results(self, results, firewall_name, vdom, df, fields, result_type=None):
        """Generic function to process results from an API call to input into a dataframe
        Args:
        result_list -- list, results passed from API call
        firewall_name -- string, name of the firewall
        vdom -- string, name of the vdom
        df -- DataFrame, the dataframe to add data to
        fields -- list of fields to add to the dataframe

        Default Args:
        result_type -- string, the type of result we are processing so we can
                       handle different results differently (default None)
        """
        # Init some things
        policy_tracker = {} # Keeps track of order of policies in each vdom
        for result in results['results']:
            # First, let's delete any fields we don't want
            [result.pop(f, 'None') for f in list(set(result.keys())-set(fields))]

            #Add firewall and vdom to the result
            result['firewall'] = firewall_name
            result['vdom'] = vdom

            # Now lets process some generic fields
            # Member fields contain a list of dicts, we just want a list of 
            # q_origin_keys
            if 'member' in fields:
                result['member'] = [x['q_origin_key'] for x in result['member']]
            # Check for FQDN and perform a DNS lookup for it if it exists
            if 'fqdn' in fields:
                if result['fqdn'] != '' or result['fqdn'] != None:
                    #result['dns-lookup'] = self.dnslookup(result['fqdn'])
                    result['dns-lookup'] = None # TODO Remove, here for testing
                else:
                    result['dns-lookup'] = None
            # Check for subnet fields and convert start and end into long ints
            if 'subnet' in fields:
                network = self.convert_subnet(result['subnet'])
                result['start-ip'] = self.iptolong(network[0])
                result['end-ip'] = self.iptolong(network[-1])

            # Now lets handle more specific edge cases
            # Handle policies
            if result_type == 'policies':
                # TODO Handle policies with multiple src/dstintfs
                srcintf = result['srcintf'][0]['name']
                dstintf = result['dstintf'][0]['name']
                result['dstaddr'] = tuple([x['q_origin_key'] for x in result['dstaddr']])
                result['srcaddr'] = tuple([x['q_origin_key'] for x in result['srcaddr']])
                result['srcintf'] = [x['q_origin_key'] for x in result['srcintf']][0]
                result['dstintf'] = [x['q_origin_key'] for x in result['dstintf']][0]
                result['service'] = tuple([x['q_origin_key'] for x in result['service']])
                if srcintf not in policy_tracker.keys():
                    policy_tracker[srcintf] = {}
                if dstintf not in policy_tracker[srcintf].keys():
                    policy_tracker[srcintf][dstintf] = 0
                result['order'] = policy_tracker[srcintf][dstintf]
                policy_tracker[srcintf][dstintf] += 1

            # Handle routing tables
            if result_type == 'routing_tables':
                network = self.convert_subnet(result['ip_mask'])
                if result['ip_mask'] == '0.0.0.0/0':
                    result['outside_interface'] = True
                else:
                    result['outside_interface'] = False
                result['start-ip'] = self.iptolong(network[0])
                result['end-ip'] = self.iptolong(network[-1])
                try:
                    result['gateway'] = self.iptolong(self.convert_subnet(result['gateway'])[0])
                except: result['gateway'] = ""

            # Handle services. Note, that since the tcp/udp range fields
            # are a string of space separated ranges or single addresses, like such
            # tcpranges = '22 100-1000 50'
            # So to make this easily searchable, we make a new row in the DataFrame
            # for each set of tcp/udp ranges. If its a single address, the low and high
            # is the same. We can do a groupby(service_name) in the DataFrame when selecting later
            if result_type == 'services':
                # if we have protocol number as 0, its an allow all
                if result['protocol-number'] == 0:
                    result['tcp_low'] = 0
                    result['tcp_high'] = 65535
                    result['udp_low'] = 0
                    result['udp_high'] = 65535
                else:
                    new_result = []
                    tcps = result['tcp-portrange'].split(' ')
                    udps = result['udp-portrange'].split(' ')
                    pairs = izl(tcps, udps, fillvalue="")
                    for pair in pairs:
                        tcp = pair[0].split(':')[0].split('-')
                        tcp += [tcp[0]]  * (2-len(tcp))
                        udp = pair[1].split(':')[0].split('-')
                        udp += [udp[0]] * (2-len(udp))
                        result['tcp_low'] = int(tcp[0]) if tcp[0] != '' else ''
                        result['tcp_high'] = int(tcp[1]) if tcp[1] != '' else ''
                        result['udp_low'] = int(udp[0]) if udp[0] != '' else ''
                        result['udp_low'] = int(udp[1]) if udp[1]!= '' else ''
                        new_result.append(result)
                    result = new_result

            # Finally, add the result to the dataframe
            # TODO the append function creates a copy of the dataframe, this is slow
            # I should just create a list of dicts to insert instead
            df = df.append(result, ignore_index=True)
        return df

    def mark_outside_interfaces(self, vdom, df):
        # Select any interface thats marked as outside
        for name in df.loc[(df['outside_interface']==True) & (df['vdom']==vdom), 'interface']:
            df.loc[(df['interface']==name) & (df['vdom']==vdom), 'outside_interface'] =  True
        return df

    def disconnect(self, fgtconn):
        """Terminates the current session to a firewall.
        Args:
        fgtconn -- connection opened by self.connect()
        """
        try:
            fgtconn.logout()
            return
        except Exception as e:
            raise Exception("Could not logout: {}".format(e))


    def parse_all(self, firewall='all'):
        """Parses everything we can from firewalls.
        Args:
        firewall -- firewall (section) to parse. If 'all', will parse all sections
        in the config file
        """
        if firewall == 'all':
            scp = ConfigParser.SafeConfigParser()
            scp.read(self.config_file)
            for section in scp.sections():
                fgt = self.connect(section=section)
                # Routing Tables
                self.get_routing_tables(fgt, section)
                self.get_policies(fgt, section)
                self.get_addresses(fgt, section)
                self.get_services(fgt, section)
                self.get_address_groups(fgt, section)
                self.get_service_groups(fgt, section)
                self.disconnect(fgt)
def main():
    c = "/etc/fortinet/config.conf"
    F = FortiParser(config_file=c)
    F.parse_all()
    code.interact(local=locals())
if __name__ == "__main__":
    main()
