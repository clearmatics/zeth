#!/usr/bin/sage

"""
Computes the valid configurations of mimc for ALT-BN128 and BLS12-377 and
the number of multiplications required.
"""

def mults_to_combine_num_powers(num_powers):
    num_powers_bits = num_powers.bits()
    num_powers_true_bits = sum(num_powers_bits)
    assert 0 != num_powers_true_bits

    # Compute largest pow2 group of exponents
    pow2_group = 1 << (len(num_powers_bits) - 1)
    # remaining exponents
    num_powers = num_powers - pow2_group
    # cost to combine the pow2_group into a single power
    mults = pow2_group - 1

    # No more powers to multiply together
    if num_powers == 0:
        return mults

    # Total cost:
    #   mults + <cost to combine this with remaining powers>
    return mults + mults_to_combine_num_powers(1 + num_powers)


def compute_mults(e):
    """
    For e = 2^t - 1, mults can be computed as 2*t - 2, but we implement a more
    general function.
    """
    e_bits = e.bits()
    e_true_bits = sum(e_bits)   # num true bits
    # 1 multiplication for each exponent used
    mults = len(e_bits) - 1
    # combine e_true_bits
    return mults + mults_to_combine_num_powers(e_true_bits)


def output_valid_config_and_constraints(r, log_2_r, e):
    if 1 == gcd(r-1, e):
        mults = compute_mults(e)
        rounds = ceil(log_2_r / log(e, 2))
        constraints = mults * rounds + 1
        print(f"  e={e}, rounds={rounds}, mults={mults}, constraints={constraints}")


def output_valid_configs_and_constraints(r):
    log_2_r = log(r, 2)
    for t in range(2, 22):
        e = (1 << t) - 1
        output_valid_config_and_constraints(r, log_2_r, e)
        e = (1 << t) + 1
        output_valid_config_and_constraints(r, log_2_r, e)

    # TODO: determine if these value are valid
    # output_valid_config_and_constraints(r, log_2_r, 11)
    # output_valid_config_and_constraints(r, log_2_r, 13)
    # output_valid_config_and_constraints(r, log_2_r, 17)
    # output_valid_config_and_constraints(r, log_2_r, 19)
    # output_valid_config_and_constraints(r, log_2_r, 23)


# BW6-761
print("BW6-761:")
output_valid_configs_and_constraints(
    r=258664426012969094010652733694893533536393512754914660539884262666720468348340822774968888139573360124440321458177)

# MNT4
print("MNT4:")
output_valid_configs_and_constraints(
    r=475922286169261325753349249653048451545124878552823515553267735739164647307408490559963137)

# MNT6
print("MNT6:")
output_valid_configs_and_constraints(
    r=475922286169261325753349249653048451545124879242694725395555128576210262817955800483758081)

# BLS12-377
print("BLS12-377:")
output_valid_configs_and_constraints(
    r=0x12ab655e9a2ca55660b44d1e5c37b00159aa76fed00000010a11800000000001)

print("ALT-BN128:")
output_valid_configs_and_constraints(
    r=0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001)
