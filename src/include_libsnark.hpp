#pragma once

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdelete-non-virtual-dtor"

#ifdef ZKSNARK_GROTH16
# include "libff/algebra/fields/field_utils.hpp"
# include "libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp"
# include "libsnark/common/default_types/r1cs_ppzksnark_pp.hpp"
# include "libsnark/gadgetlib1/pb_variable.hpp"
#else
# error ZKSNARK_GROTH16 not defined
#endif

#pragma GCC diagnostic pop
