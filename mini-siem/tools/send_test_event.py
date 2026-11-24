#!/usr/bin/env python3
"""Send one synthetic log to an authorized lab collector using verified mTLS."""
import argparse
import socket
import ssl
import uuid

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--host',required=True,help='Collector DNS name matching server certificate')
p.add_argument('--port',type=int,default=6514)
p.add_argument('--ca',required=True,help='Trusted server CA PEM')
p.add_argument('--cert',required=True,help='Enrolled client certificate PEM')
p.add_argument('--key',required=True,help='Client private key PEM')
p.add_argument('--framing',choices=['octet','line'],default='octet')
a=p.parse_args()
ctx=ssl.create_default_context(cafile=a.ca)
ctx.minimum_version=ssl.TLSVersion.TLSv1_2
ctx.load_cert_chain(a.cert,a.key)
marker='lab-'+str(uuid.uuid4())
message=f'<134> action=deny test_id={marker}'.encode()
frame=str(len(message)).encode()+b' '+message if a.framing=='octet' else message+b'\n'
with socket.create_connection((a.host,a.port),timeout=5) as raw:
    with ctx.wrap_socket(raw,server_hostname=a.host) as tls:
        tls.sendall(frame)
print('Synthetic event sent:',marker)
print('No application receipt ACK; search this marker in the dashboard to verify persistence.')
