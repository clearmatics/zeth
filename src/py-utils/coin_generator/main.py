import random
import hashlib
import json
import os

from pathlib import Path
from Crypto.PublicKey import RSA

def dump_to_coinstore(data, filename, mode):
    coinstore_path = os.environ['ZETH_COINSTORE']
    coinstore_folder = Path(coinstore_path)
    coin_to_dump = coinstore_folder / filename
    fd = open(coin_to_dump, mode)
    fd.write(data)
    fd.close()

# **DUMMY** function to generate randomness (never ever ever ever use like this)
def generate_randomness():
  return random.randint(1,10000000)

# P for each coin (where P is used in the generation of sn)
# P <-- random, and sn <-- PRF_(a_sk) (P)
def generate_P():
    return generate_randomness()

def generate_r():
    return generate_randomness()

def generate_s():
    return generate_randomness()

def generate_storageID():
    return generate_randomness()

# k <-- COMM_(r) (a_pk || P)
def compute_k(r, apk, P):
    k = hashlib.sha256()
    k.update(str.encode(str(r)))
    k.update(str.encode(str(apk)))
    k.update(str.encode(str(P)))
    return k.hexdigest()

# cm <-- COMM_(s) (v || k)
def compute_cm(s, v, k):
    cm = hashlib.sha256()
    cm.update(str.encode(str(s)))
    cm.update(str.encode(str(v)))
    cm.update(str.encode(str(k)))
    return cm.hexdigest()

def get_apk(keypair_file):
    keystore_folder = Path(os.environ['ZETH_KEYSTORE'])
    keypair_to_open = keystore_folder / keypair_file
    keypair = ""
    with open(keypair_to_open) as keypair_file:
        keypair = json.load(keypair_file)
    return keypair["a_pk"]

# Mint a coin c = (apk, v, P, r, s, cm)
def mintcoin(value):
    # Retrieve apk from the keystore
    apk = get_apk("addrpair.json")

    P = generate_P()
    r = generate_r()
    s = generate_s()
    k = compute_k(r, apk, P)
    cm = compute_cm(s, value, k)

    coin_data = {}
    coin_data['apk'] = apk
    coin_data['v'] = value
    coin_data['P'] = P
    coin_data['r'] = r
    coin_data['s'] = s
    coin_data['cm'] = cm
    json_data = json.dumps(coin_data)
    coin_name = "coin-" + str(generate_storageID()) + "-value-" + str(value) + ".json"
    dump_to_coinstore(json_data, coin_name, "w")

print("Minting coin of value 7")
mintcoin(7)
