# mpc commands

(Sub)commands to perform administrative operations related to the MPC for SRS
generation. Some operations relying on the circuit-agnostic `powersoftau` data
and pre-computed Lagrange polynomials evaluations, as computed by the
`powersoftau` command.

cli executables can be implemented as `main` functions which call into the code
in this library, passing in the set of commands to make available, and a
function to generate the circuit for the MPC.

Commands are provided to:
  - generate initial "challenge" of the Phase 2 MPC
  - compute participants' responses to a given challenge
  - verify a response and create a subsequent challeng
  - verify the auditable transcript of contributions
  - create a final keypair from the MPC output
