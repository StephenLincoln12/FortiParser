import fortirest
import ConfigParser
import code
import ipaddress
import re
from pprint import pprint
import socket   
import pandas as pd
import sys
import gc


def dnslookup(fqdn):
    try:
        ip = socket.gethostbyname(fqdn)
        return ip
    except Exception as e:
        raise Exception("Could not find IP for {}: {}".format(fqdn, e))
        return None



def suggest_groups(policy_groups):
    """Goes through each policy and suggests if policies can be grouped
    together based on srcaddr's and services
    I.E: These 5 policies have the same dstaddr and allow SSH from the world,
    you should just create a SSH group and add them to it to reduce number of policies
    """
    #for group in policy_groups:
    fwname = ""
    vdom = ""
    for name, group in policy_groups:
        if name[0] != fwname:
            fwname = name[0]
            print "Firewall: {}".format(fwname)
        if name[1] != vdom:
            vdom = name[1]
            print "\tVDOM: {}".format(vdom)
        service_groups = group.groupby(['srcaddr', 'service', 'action'])
        for sname, sgroup in service_groups:
            if len(sgroup) >= 3:
                print "\t\t{} ---> {} - {}".format(name[2], name[3], sname[1])
                for ri, r in sgroup.iterrows():
                    print "\t\t\t{} {} {}".format(r['srcaddr'], r['dstaddr'], r['service'])

def find_allow_alls(F):
    """Finds allow-all policies in the firewall
    An 'Allow All' rule is defined by the following:
        The policy is enabled
        All services are allowed
        No source address is specified ('all')
        Any destination address can be specified
        The dest interface is not an 'outside' interface
    """
    # First, get a list of inside and outside interfaces (firewall, vdom, and interface)
    inside_interfaces = F.routing_tables.loc[F.routing_tables['outside_interface'] == False, ['firewall', 'vdom', 'interface']]
    outside_interfaces = F.routing_tables.loc[F.routing_tables['outside_interface'] == True, ['firewall', 'vdom', 'interface']]

    # Find allow alls
    allow_alls = F.policies.loc[(F.policies['status'] == 'enable') & \
                                (F.policies['action'].str.lower() == 'accept') & \
                                (F.policies['service'].apply(lambda x: 'all' in [x.lower() for x in x])) & \
                                (F.policies['srcaddr'].apply(lambda x: 'all' in [x.lower() for x in x]))]

    # Merge allow alls and the outside interfaces
    new = pd.merge(inside_interfaces, allow_alls, how='inner', left_on=['firewall', 'vdom', 'interface'], right_on=['firewall', 'vdom', 'dstintf'])
    
    new = new[['firewall','vdom','srcintf','dstintf','dstaddr','action','service','policyid','order','status']].drop_duplicates()


    new = pd.merge(outside_interfaces, new, how='inner', left_on=['firewall', 'vdom', 'interface'], right_on=['firewall', 'vdom', 'srcintf'])


    new = new[['firewall','vdom','srcintf','dstintf','dstaddr','action','service','policyid','order','status']].drop_duplicates().reset_index(drop=True)
    
    new.to_csv('allow_alls.csv')
    #pprint(allow_alls)
def audit_policies(F):
    """Goes through policies and checks for overlapping policies or policies that
    cancel each other out (a deny above an allow, an allow below a deny, etc)

    1) Group policies by firewall, vdom, srcintf, dstintf
    2)
    """
    # Group
    policy_groups = F.policies.sort_values(['firewall', 'vdom', 'srcintf', 'dstintf'],ascending=True).groupby(['firewall', 'vdom', 'srcintf', 'dstintf'])
    suggest_groups(policy_groups)

def search_addresses(F, object_name, firewall=None, vdom=None):
    """Searches address and address group DataFrames to find any object matching
    object_name. Returns array of dicts of results, or None if it couldn't find
    anything. If it's a group, it will indicate it's an address group and return
    the members of all of the group, and any groups in the group

    Args:
    F -- class instance of fortirest
    object_name -- string, name of address (or group) to search for

    Default Args:
    firewall -- string, specify a firewall to search in. If None, will search
                through all firewalls (Default None)
    vdom -- string, specify a VDOM to search in. If None, will search through
            all VDOMs
    """
    #TODO groups. For now to keep it simple, we'll just do addresses.

    found =  F.addresses.loc[F.addresses['name'].str.lower() == object_name.lower()]
    if len(found) == 0:
        return None
    else:
        return found

def search_routing_tables(F, firewall=None, vdom=None, ip=None, name=None, case_sensitive=False):
    """
    Will determine what firewall, VDOM, and interface an IP/FQDN/Address Object
    (or Address Object Group) is behind based on routing tables in each firewall
    If looking up by name, will find the name in the address object list and
    then perform a lookup by it's IP, because you know as well as I do, we can't trust
    people to put address objects in the correct interface
    If the IP is not behind the firewall according to the routing table,
    the address object is misplaced and probably old/outdated and will be reported as such.

    Note that this will ignore all interfaces that are marked as 'outside', as
    outside interfaces are defined as 0.0.0.0/0 which matches everything.

    Args:
    F -- class instance of fortirest

    Default Args
    ip -- IP Address, either single IP or CIDR notation (default: None)
    firewall -- string, allows user to specify firewall to search, if None, will
                search all firewalls (Default None)
    vdom -- string, allows user to specify VDOM to search, if None, will search
            all VDOMS (Default None)
    name -- Address Object or FQDN, since we do the dnslookups after we parse
            address objects in fortirest, we don't need to do another one
            we can just check the address object DataFrame (default None)
    case_sensitive -- Boolean for case sensitivity when looking up 'name' (default: False)
    """

    # If we have an address name, get it's IP(s)
    to_return = []
    
    if name != None:
        ips = []
        addresses = search_addresses(F, name, firewall=firewall, vdom=vdom)
        # TODO - I'm going to be doing this a lot, make it a decorator
        addresses = [addresses] if not isinstance(addresses, list) else addresses
        pprint(addresses)
        for a in addresses:
            ips.append({'start': a['start-ip'].values[0],
                        'end': a['end-ip'].values[0],
                        'name': name})

    if ip:
        # Check for CIDR notation
        ipv4_cidr_re = re.compile('^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/(3[0-2]|[1-2][0-9]|[0-9]))$')
        ipv4_re = re.compile('^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$')

        if not ipv4_cidr_re.match(ip):
            if not ipv4_re.match(ip):
                raise Exception('IP {} is not in the correct format. Please use a correct IP address with or without CIDR notation')
                return None
            else:
                ip += unicode('/32')
        
        # Do the lookup in the routing tables
        ipn = ipaddress.IPv4Network(ip)
        ips = [{'start': int(ipn[0]),
                'end': int(ipn[-1]),
                'name': ip}]

    for i in ips:
        pprint(i)
        to_return.append(F.routing_tables.loc[(F.routing_tables['start-ip'] <= i['start']) & \
                             (F.routing_tables['end-ip'] >= i['end']) & \
                             (F.routing_tables['outside_interface'] == False)])
    return to_return

def get_obj_size(obj):
    """Pick an object, any object, and it will get the size of it (in bytes)
    This is useful for checking to make sure we wont fill up RAM by creating
    a new in-memory db
    """
    marked = {id(obj)}
    obj_q = [obj]
    sz = 0

    while obj_q:
        sz += sum(map(sys.getsizeof, obj_q))
        all_refr = ((id(o), o) for o in gc.get_referents(*obj_q))
        new_refr = {o_id: o for o_id, o in all_refr if o_id not in marked and not isinstance(o, type)}
        obj_q = new_refr.values()
        marked.update(new_refr.keys())
    return sz

def main():
    # Check for basic load arg, can be anything
    try:
        load = sys.argv[1]
    except:
        load = None

    # Set config path, create instance of the Fortiparser class
    c = "/etc/fortinet/config.conf"
    F = fortirest.FortiParser(config_file=c)

    # Read config file
    scp = ConfigParser.SafeConfigParser()
    scp.read(c)

    # If we don't want to load a previous instance, create a new one and save it
    if not load:
        for fwname in scp.sections():
            F.parse_all()
        for name in F.dataframe_names:
            tmp = getattr(F, name)
            tmp.to_pickle(name+'.pkl')

    # Else, load it from files - less time than re-creating
    else:
        for name in F.dataframe_names:
            setattr(F,name,pd.read_pickle(name+'.pkl'))
    code.interact(local=dict(globals(), **locals())) 
if __name__ == "__main__":

    main()
