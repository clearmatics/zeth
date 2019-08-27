

int zeth_mpc_dummy_layer2(const std::vector<std::string> &args)
{
    cli_options options;
    try {
        options.parse(args);
    } catch (po::error &error) {
        std::cerr << " ERROR: " << error.what() << std::endl;
        std::cout << std::endl;
        options.usage();
        return 1;
    }

    // Execute and handle errors

    try {
        return zeth_mpc_new_main(options);
    } catch (std::invalid_argument &error) {
        std::cerr << " ERROR: " << error.what() << std::endl;
        std::cout << std::endl;
        return 1;
    }
}
