import ecdsa
import base64
import json
import config
import os
import hashlib
import getpass
import json

if not os.path.isfile(config.admin_privkey):
   print 'It appears there is no admin key, assuming you\'re using a passphrase, please enter it below'
   passphrase = getpass.getpass('Passphrase: ')
   key_hash   = hashlib.sha256(passphrase).digest()
   sk         = ecdsa.SigningKey.from_string(key_hash, curve=ecdsa.NIST256p)
else:
   fd = open(config.admin_privkey,'r')
   sk = ecdsa.SigningKey.from_pem(fd.read())
   fd.close()

fd = open(config.node_cert,'r')
cert_outer = json.load(fd)
fd.close()

cert_inner_b64          = base64.b64decode(cert_outer['inner'])
cert_inner              = json.loads(cert_inner_b64)
cert_outer['certsig']   = sk.sign_deterministic(cert_outer['inner']).encode('hex')
cert_outer['pubkeysig'] = sk.sign_deterministic(cert_inner['pubkey'].decode('hex')).encode('hex')

fd = open(config.node_cert,'w')
json.dump(cert_outer,fd)
fd.close()
