template<typename FieldT, typename HashT>
int setupCommand(Miximus<FieldT, HashT> prover) {
    std::cout << "Running the trusted setup..." << std::endl;
    prover.generate_trusted_setup();
    std::cout << "Trusted setup successfully generated" << std::endl;
    return 0;
}
