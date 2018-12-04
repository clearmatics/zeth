# Coinstore repository for Zeth

Contains the list of all coins owned by a user.

## TODO

In order to make this PoC more resilient to faults, on ecan imagine a nackup mechanism for both the
`coinstore`, and the `keystore`.
The encrypted broadcast mechanism introduced in the protocol, makes the software robust against loss of coins, as
one can just scan the blockchain with his keys to recover all of his payments. However, having a backup of one's keys
could be a great way to avoid re-scanning the entire chain.
