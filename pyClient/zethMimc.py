from random import randint

try:
    # pysha3
    from sha3 import keccak_256
except ImportError:
    # pycryptodome
    from Crypto.Hash import keccak
    keccak_256 = lambda *args: keccak.new(*args, digest_bits=256)

from zethConstants import ZETH_MIMC_PRIME, ZETH_MIMC_IV_MT

class MiMC7:
    iv = b"mimc"

    def __init__(self, iv = b"mimc", prime=ZETH_MIMC_PRIME):
        self.prime = prime
        self.iv = iv

    def MiMCRound(self, message, key, rc):
        xored = (message + key + rc) % self.prime
        return xored ** 7 % self.prime

    def encrypt(self, message, ek, iv = iv, rounds = 91):
        round_constant = self.sha3_256(iv) #in the paper the first round constant is 0
        res = self.toInt(message) % self.prime
        key = self.toInt(ek) % self.prime
        for i in range(rounds):
            round_constant = self.sha3_256(round_constant)
            res = self.MiMCRound(res, key,  self.toInt(round_constant))
        return (res + key) % self.prime

    def hash(self, messages, iv):
        hash = 0
        key = self.toInt(iv) % self.prime
        if len(messages) == 0:
            return
        else:
            for i in range(len(messages)):
                hash = self.encrypt(messages[i], key) % self.prime
                key = ( self.toInt(messages[i]) + hash + key) % self.prime
            return key

    def toInt(self, value):
        if type(value) != int:
            if type(value) == bytes:
               return int.from_bytes(value, "big")
            elif type(value) == str:
                return int.from_bytes(bytes(value, "utf8"), "big")
            else:
                return -1
        else :
            return value

    def to_bytes(self, *args):
        for i, _ in enumerate(args):
            if isinstance(_, str):
                yield _.encode('ascii')
            elif not isinstance(_, int) and hasattr(_, 'to_bytes'):
                # for 'F_p' or 'FQ' class etc.
                yield _.to_bytes('big')
            elif isinstance(_, bytes):
                yield _
            else:
                # Try conversion to integer first?
                yield int(_).to_bytes(32, 'big')


    def sha3_256(self, *args):
        data = b''.join(self.to_bytes(*args))
        hashed = keccak_256(data).digest()
        return int.from_bytes(hashed, 'big')

    def all_tests(self):
        print("\nRunning tests")
        m1 = 3703141493535563179657531719960160174296085208671919316200479060314459804651
        m2 = 134551314051432487569247388144051420116740427803855572138106146683954151557
        m3 = 918403109389145570117360101535982733651217667914747213867238065296420114726
        res  = 0
        if (self.sha3_256(b"Clearmatics") != ZETH_MIMC_IV_MT):
            print("SHA3 error:", self.sha3_256(b"Clearmatics"), "instead of", ZETH_MIMC_IV_MT)
            res += 1

        if (self.encrypt(m1,m2) != 11437467823393790387399137249441941313717686441929791910070352316474327319704):
            print("Encrypt error:", self.encrypt(m1,m2), "instead of", 11437467823393790387399137249441941313717686441929791910070352316474327319704)
            res +=2

        if (self.hash([m1, m2], m3) != 15683951496311901749339509118960676303290224812129752890706581988986633412003):
            print("Hash error", self.hash([m1, m2], m3), "instead of", 15683951496311901749339509118960676303290224812129752890706581988986633412003)
            res +=4
        if res == 0:
            print("Tests passed")

    def generate_random_hash(self, verbose = 1):

        m0 = randint(0, self.prime-1)
        m1 = randint(0, self.prime-1)
        iv = randint(0, self.prime-1)
        h = self.hash([m0,m1], iv)
        if verbose < 5:
            print("\n-------------------- Generate random hash")
            print("h = mimc_hash([m0, m1], iv)")
            print("m0:", m0)
            print("m1:", m1)
            print("iv:", iv)
            print("h:", h)
        return m0, m1, iv, h

    def generate_left_nested_hash(self, verbose = 1):
        m0, m1, iv, h = self.generate_random_hash(verbose)
        m2 = randint(0, self.prime-1)
        iv2 = randint(0, self.prime-1)
        h2 = self.hash([h, m2], iv2)
        if verbose < 5:
            print("\n-------------------- Generate imbricated hash")
            print("h' = mimc_hash([h, m2], iv2)")
            print("h:", h)
            print("m2:", m2)
            print("iv2:", iv2)
            print("h:", h2)
        return h2

    def generate_right_nested_hash(self, verbose = 1):
        m0, m1, iv, h = self.generate_random_hash(verbose)
        m2 = randint(0, self.prime-1)
        iv2 = randint(0, self.prime-1)
        h2 = self.hash([m2, h], iv2)
        if verbose < 5:
            print("\n-------------------- Generate imbricated hash")
            print("h' = mimc_hash([h, m2], iv2)")
            print("h:", h)
            print("m2:", m2)
            print("iv2:", iv2)
            print("h:", h2)
        return h2

    def generate_tree(self, depth=2, iv = ZETH_MIMC_IV_MT, verbose = 1):
        if depth >10:
            print("tree too deep")
            return

        print("\n-------------------- Generate tree of depth", depth)

        leaves = []
        print("\nLeaves")
        for i in range(2**depth):
            leaf = self.generate_left_nested_hash(verbose)
            leaves.append(leaf)
            if verbose >= 5:
                print(leaf)

        nodes = [leaves]
        for i in range(1,depth+1):
            if i != depth:
                print("\nLevel "+str(depth-i))
            else:
                print("\nRoot")
            level = []
            for j in range(len(nodes[i-1])//2):
                level.append(self.hash([nodes[i-1][2*j], nodes[i-1][2*j+1]], iv))
                print(level[j])
            nodes.append(level)
        return nodes


def test_sha3():
    m = MiMC7()
    assert m.sha3_256(b"Clearmatics") == 14220067918847996031108144435763672811050758065945364308986253046354060608451

def test_encrypt():
    m = MiMC7()
    m1 = 3703141493535563179657531719960160174296085208671919316200479060314459804651
    m2 = 134551314051432487569247388144051420116740427803855572138106146683954151557
    assert m.encrypt(m1,m2) == 11437467823393790387399137249441941313717686441929791910070352316474327319704

def test_hash():
    m = MiMC7()
    m1 = 3703141493535563179657531719960160174296085208671919316200479060314459804651
    m2 = 134551314051432487569247388144051420116740427803855572138106146683954151557
    m3 = 918403109389145570117360101535982733651217667914747213867238065296420114726
    assert m.hash([m1, m2], m3) == 15683951496311901749339509118960676303290224812129752890706581988986633412003


def main():
    m = MiMC7()
    m.all_tests()


if __name__ == "__main__":
    import sys
    sys.exit(main())
