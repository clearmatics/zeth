# Zeth Prover Server

This component listens for incoming "proof generation" requests, generates the proof and returns it to the caller.

Note that this program is seen as a daemon running on the machine of the Zeth user. It can be deployed on a different machine but care will need to be taken to make sure that the witness is protected while communicating with the server. This is out of scope of this work.
