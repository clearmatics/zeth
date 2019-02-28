# Coinstore repository for Zeth

Contains the list of all Zeth notes owned by a user.

## Note

The encrypted broadcast used in ZETH - to send the ZETH notes to the recipient - presents some nice features when we consider hardware failures or loss of notes data. In fact, one can easily set up a backup routine that periodically backs up the content of the coinstore, and more importantly, that backs up
the keystore.
In fact, having access to their decryption keys enable users to scan the entire chain and look into the logs of the zeth mixer contract to try and decrypt 
all the ciphertexts to recover the list of notes they control.
Backing up the coinstore along the keystore could avoid the overhead of scanning the blockchain after a hardware failure. Having access to one's list of notes present several other nice features, but we refer the reader to the paper for more details on the design of ZETH.
