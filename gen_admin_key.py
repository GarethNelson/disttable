import ecdsa
import hashlib
import getpass
import sys
import time
import config

print 'Let\'s create an admin key for you'
print 'If you wish to generate your key deterministically from a memorable passphrase, please type it below, otherwise just hit enter'

save_privkey = False
passphrase = getpass.getpass('Passphrase: ')
if len(passphrase)==0:
   print 'No passphrase entered, a random key will be generated for you'
   fd = open('/dev/urandom','r')
   passphrase = fd.read(1024)
   passphrase_confirm = passphrase
   fd.close()
   save_privkey = True
else:
   passphrase_confirm = getpass.getpass('Confirm passphrase: ')

if passphrase_confirm != passphrase:
   print 'Passphrases did not match! Try again'
   sys.exit()

if not save_privkey:
   print 'Please note that your private key will NOT be saved to disk'
   print 'If you would like to do so please type "yes" below'
   save_to_disk = input()
   if save_to_disk.startswith('yes'):
      save_privkey = True

print 'Generating keypair...'

key_hash = hashlib.sha256(passphrase).digest()
sk = ecdsa.SigningKey.from_string(key_hash,curve=ecdsa.NIST256p)
vk = sk.get_verifying_key()

if save_privkey:
   print 'Saving private key'
   sk_pem = open(config.admin_privkey,'w')
   sk_pem.write(sk.to_pem())
   sk_pem.close()
   print 'Saved to %s' % config.admin_privkey
else:
   print 'Your private key has not been saved to disk'
   print 'Please make sure you do not forget your passphrase as you can NOT recover it later if you forget it'


print 'Saving public key'
vk_pem = open(config.admin_pubkey,'w')
vk_pem.write(vk.to_pem())
vk_pem.close()
print 'Saved to %s' % config.admin_pubkey

print 'All done!'

