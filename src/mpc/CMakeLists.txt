# Build for mpc utilities

# library of mpc subcommands
file(GLOB MPC_CLI_SOURCE cli/*.?pp mpc/*.tcc)
add_library(mpc-cli ${MPC_CLI_SOURCE})
target_include_directories(mpc-cli PUBLIC cli)
target_link_libraries(
  mpc-cli
  zeth
  ${Boost_SYSTEM_LIBRARY}
  ${Boost_PROGRAM_OPTIONS_LIBRARY}
)

# mpc administrator executable
add_executable(mpc mpc.cpp)
target_link_libraries(mpc mpc-cli)

# mpc test utility
add_executable(mpc-test test/mpc_test_cli.cpp)
target_link_libraries(mpc-test mpc-cli)
