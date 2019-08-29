# mpc command

Performs administrative operations related to the MPC for SRS generation.
Operations performed by this command are specific to the constraint system used
by zeth, relying on the circuit-agnostic `powersoftau` data and pre-computed
Lagrange polynomials evaluations, as computed by the `powersoftau` command.

This command can be used to generate the linear-combination data, which forms
the initial "challenge" of the Phase 2 MPC.  Participants compute a "resonse"
for their challenge, which is then processed to create a final keypair and an
auditable transcript of contributions.

For the full list of options, see output of `mpc --help`.
