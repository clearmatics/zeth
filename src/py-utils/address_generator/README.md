# Address generator

This python modules generates addresses in the form:

> (addr_pub, addr_priv)

such that `addr_pub = (a_pk, e_pk)`, and `addr_priv = (a_sk, e_sk)`.

Here, `a_pk`, and `a_sk` represent the public/private key pair that is used to commit new coins to a user of the system. On the other hand, `e_pk`, and `e_sk`, are used to encrypt the coin's data when it is sent to the new recipient.

**Note:** `a_sk`, and `e_sk` should **remain secret**.
