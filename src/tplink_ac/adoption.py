"""Shared admission policy for discovery, DTLS and configuration writes."""
import ipaddress

def permitted(config,ip,mac=None):
    if not config.get('enabled'): return False
    mode=config.get('ap_metadata',{}).get(mac,{}).get('adoption','default')
    if mode=='block': return False
    if mode=='allow' or ip in config.get('allowed_ips',[]): return True
    return config.get('auto_adopt',False) and any(
        ipaddress.ip_address(ip) in ipaddress.ip_network(net) for net in config.get('adopt_subnets',[]))
