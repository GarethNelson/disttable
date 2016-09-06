import ecdsa
import hashlib
import sys
import time
import config
import json
import base64
import uuid

print 'Generating node keypair'
sk = ecdsa.SigningKey.generate(curve=ecdsa.NIST256p)
vk = sk.get_verifying_key()
print 'Saving keypair to disk'

node_pub = open(config.node_pubkey,'w')
node_pub.write(sk.to_pem())
node_pub.close()

node_priv = open(config.node_privkey,'w')
node_priv.write(vk.to_pem())
node_priv.close()

print 'Ready to create certificate'
inner_cert = {}

inner_cert['nodeid']  = str(uuid.uuid1())
inner_cert['pubkey']  = vk.to_string().encode('hex')
inner_cert['created'] = time.ctime()

cert_json = json.dumps(inner_cert)
cert_b64  = base64.b64encode(cert_json)

cert = {'inner':cert_b64,
        'certsig':None,
        'pubkeysig':None}

cert_file = open(config.node_cert,'w')
cert_file.write(json.dumps(cert))
cert_file.close()

print 'Created certificate and saved to %s, please sign it using sign_node_cert.py on a secure machine' % config.node_cert
