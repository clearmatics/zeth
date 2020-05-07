# pot-process command

Command for processing powersoftau data (output from commands in
https://github.com/clearmatics/powersoftau), independent of any
specific circuit. Main use-case is to pre-compute the evaluations of
the Lagrange polynomials for domains of specific sizes, so that this
data can be used during the remaining steps of the SRS computation,
across multiple circuits.

`pot-process` command can also be used to verify powersoftau data, and
to generate "dummy" powersoftau data (that is, based purely on local
randomness with no MPC) for testing.

For usage details, see output of `pot-process --help`
