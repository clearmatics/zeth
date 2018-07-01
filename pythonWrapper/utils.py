import hashlib
import random 

def hex2int(elements):
    ints = []
    for e in elements:
        ints.append(int(e, 16))
    return(ints)

def bytesToBinary(hexString):
    out = "" 
    for i, byte in enumerate(hexString):
        out += bin(byte)[2:].rjust(8,"0")
    out = [int(x) for x in out] 
    return((c.c_bool*256)(*out))

def generateSalt(i):
    salt = [random.choice("123456789abcdef") for x in range(0,i)]
    out = "".join(salt)
    return(out)

def generateNullifier(recvAddress):
    salt = generateSalt(24)
    return(recvAddress + salt)

def generateSecret():
    secret = generateSalt(64)
    return secret

def computeCommitment(nullifier, secret):
    m = hashlib.sha256()
    m.update(bytearray.fromhex(nullifier[2:]))
    m.update(bytearray.fromhex(secret))
    return m.hexdigest()

# We differentiate between leaf address (which is the position of a leaf in the leaf array)
# And the address of a node which is the address of a node in the tree
# For example, in a tree of depth 4, there are 2^4 leaves, and there are 2^5 - 1 nodes
# Thus the leafAddress of the first leaf is: 0 (first element of the leaf array)
# and its nodeAddress is 16 (because the same leaf appears in the 16th position in the array of nodes of the tree)
def convertLeafAddressToNodeAddress(addressLeaf, tree_depth):
    address = addressLeaf + 2 ** tree_depth
    if(address > 2 ** (tree_depth+1) - 1): # Total number of nodes in the tree, so if address > to this, the address given is invalid
        return -1 # return empty merkle_path
    return address

def computeMerklePath(addressCommitment, tree_depth, tree):
    merkle_path = []
    address_bits = []
    address = convertLeafAddressToNodeAddress(addressCommitment, tree_depth)
    if(address == -1):
        return merkle_path # return empty merkle_path
    for i in range (0 , tree_depth):
        address_bits.append(address % 2)
        if (address %2 == 0) :
            merkle_path.append(tree[address + 1])
        else:
            merkle_path.append(tree[address - 1])
        address = int(address/2) 
    return merkle_path[::-1]
