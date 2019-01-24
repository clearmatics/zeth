// This file should be wrapper around the prover circuit and should basically generate 
// all the data necessary to be fed into the gagdets (ie: this function should build the witness)
// Once the assignement of the circuit is built, we should call the circuits/gagdets with
// the appropriate input and generate the proof

// We want all our gadgets to respect the common gadget interface (ie: implement the
// "generate_r1cs_constraints" and the "generate_r1cs_witness" functions)
// This file should wrap everything around, call the functions to do I/O of the proof, and parse the
// user input to feed it into the gadgets.

// The idea is to have somehting like zcash did here: https://github.com/zcash/zcash/blob/0f091f228cdb1793a10ea59f82b7c7f0b93edb7a/src/zcash/circuit/gadget.tcc
// This gadget basically imports all other gadgets (subcircuits) in order to
// build the joinsplit circuit which is the main gadget/whole circuit
// Then the .tcc circuit is wrapped by cpp code that parses everything that needs to be fed into
// the circuit