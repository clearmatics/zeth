import random
import hashlib
import json
import os

from pathlib import Path
from Crypto.PublicKey import RSA

def dump_to_keystore(data, filename, mode):
    keystore_path = os.environ['ZETH_KEYSTORE']
    # See https://medium.com/@ageitgey/python-3-quick-tip-the-easy-way-to-deal-with-file-paths-on-windows-mac-and-linux-11a072b58d5f
    # for use of pathlib
    keystore_folder = Path(keystore_path)
    file_to_dump = keystore_folder / filename
    fd = open(file_to_dump, mode)
    fd.write(data)
    fd.close()

# **Dummy** function to generate a_sk for each user
# a_sk <-- taken at random
def generate_ask():
  apk = random.randint(1,10000000)
  return apk

# a_pk <-- PRF_(a_sk) (0), with PRF = sha256 here
def generate_apk(ask):
    apk = hashlib.sha256()
    apk.update(str.encode(str(apk)))
    apk.update(str.encode(str(0)))
    return apk.hexdigest()

# Generate a key pair (a_pk, a_sk) and dump it into a file
def addrgen():
    ask = generate_ask()
    apk = generate_apk(ask)
    data = {}
    data['a_sk'] = ask
    data['a_pk'] = apk
    json_data = json.dumps(data)
    dump_to_keystore(json_data, "addrpair.json", "w")

# See: https://medium.com/@ismailakkila/black-hat-python-encrypt-and-decrypt-with-rsa-cryptography-bd6df84d65bc
# For keygen
def keygen():
    new_key = RSA.generate(4096, e=65537)
    private_key = new_key.exportKey("PEM")
    public_key = new_key.publickey().exportKey("PEM")
    dump_to_keystore(private_key, "private_key.pem", "wb")
    dump_to_keystore(public_key, "public_key.pem", "wb")

ask = generate_ask()
print("Generate a_sk result: ", ask)
print("Generate a_pk result: ", generate_apk(ask))

print("Encryption-Decryption key pair generation")
keygen()

print("Addr pair generation")
addrgen()
