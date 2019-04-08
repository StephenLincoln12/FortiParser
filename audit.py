import fortirest
import ConfigParser
import code
import ipaddress
import re
from pprint import pprint
import socket   
import pandas
import sys
import gc


def dnslookup(fqdn):
    try:
        ip = socket.gethostbyname(fqdn)
        return ip
    except Exception as e:
        raise Exception("Could not find IP for {}: {}".format(fqdn, e))
        return None


def audit_policies(F):
    """Goes through policies
    For each srctinf->dstintf:
        For each policy (top down):
            check for allow all to everything (red flag), excpt to outside?
            check for allow all services (warn)
            get src addresses (cidr) and dst addresses (cidr)
            get ports open/closed
            for p in policies[i+1:]:
    """
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
        ipn = IPv4Network(ip)
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
    c = "/etc/fortinet/config.conf"
    F = fortirest.FortiParser(config_file=c)
    scp = ConfigParser.SafeConfigParser()
    scp.read(c)
    for fwname in scp.sections():
        conn = F.connect(section="OPS") 
        F.get_addresses(conn, "OPS")
        F.get_routing_tables(conn, fwname)
        F.disconnect(conn)
        break
    print search_routing_tables(F, name='ARCWEB01.UITS.UCONN.EDU')
    code.interact(local=locals())
if __name__ == "__main__":

    main()
