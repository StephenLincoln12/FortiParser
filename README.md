# FortiParser

I didn't feel like manually looking through firewalls to find stuff
or audit policies so I did this

## Requirements
**Python 2.7** - Yes, I know its EOL soon. Yes, I'll port it to 3
[**ftntlib**:](https://github.com/jpforcioli/ftntlib) - Wrapper for the Fortinet REST API
[**pandas**:](https://pandas.pydata.org/) - Data structure for holding all the firewall(s) data


## HOW TO

### SETUP

Install all the requirements. Also, make sure you have an account you can use
to login to all the firewalls you want to read from, preferably from a read-only service account that is IP restricted.

Create a config file somewhere (default is `/etc/fortinet/config.conf` that can be read by ConfigParser. If you put the config in somewhere else, change the location in `main()` at the bottom of fortirest.py.

Wherever you put it, the format should be as follows:

```
[Example Firewall Name 1]
ip = 127.0.0.1
username=AzureDiamond
password=hunter2
hostname=hunter2.fw.irc.net

[Example Firewall Name 2]
ip = 127.0.0.2
username=default
password=creds
hostname=changeme.fw.net
```

You need to supply either an IP or hostname, but the config must contain both keys; the value of one or the other can be blank.

### HOW DOES IT WORK

This will connect to all the firewalls listed in the config and parse the relevent information into pandas dataframes (df).  Df tables are as follows:

- routing_tables
- addresses
- address_groups
- services
- service_groups
- policies

See docstrings for a more complete description of dataframes and default fields in each one. Some important things to note though:

- Networks are split up into start-ip and end-ip fields
- IP Addresses are stored as longints
- Interfaces are considered 'outside' if traffic from the internet routes through it. Everything else is considered internal and not an 'outside' interface.

### USAGE
```python audit.py [load]``` This will return an interactive interpreter prompt so you can play around with the dataframes.  If you supply 'load' as the first arg, it will load a previously saved instance of the class that contains all the dataframes; as of now, parsing all the data is slow and speeding it up is on my list of things to fix.  

### TODO
- Speed up GETing the data
- More auditting functions, including finding overlapping policies, stale address objects
- Organize it better
- Python 3 support
