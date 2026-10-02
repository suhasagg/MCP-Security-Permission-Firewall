import ipaddress,socket
from urllib.parse import urlparse
def validate_endpoint(url):
    u=urlparse(url)
    if u.scheme!="https": return False,"https required"
    if not u.hostname:return False,"hostname required"
    try:
        for info in socket.getaddrinfo(u.hostname,None):
            ip=ipaddress.ip_address(info[4][0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
                return False,"private/link-local/reserved destination denied"
    except OSError:return False,"dns resolution failed"
    return True,"ok"
