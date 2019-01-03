template<typename ppT, typename HashT>
int setupCommand(Miximus<ppT, HashT> &prover) {
    std::cout << "Running the trusted setup..." << std::endl;
    prover.generate_trusted_setup();
    std::cout << "Trusted setup successfully generated" << std::endl;
    return 0;
}
