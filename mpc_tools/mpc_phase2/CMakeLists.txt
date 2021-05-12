# Build for mpc phase2 utilities

# library of mpc subcommands
file(
  GLOB
  MPC_CLI_SOURCE
  cli/*.?pp
)

add_library(
  mpc-cli

  ${MPC_CLI_SOURCE}
)
target_include_directories(mpc-cli PUBLIC cli)
target_link_libraries(
  mpc-cli
  zeth
  tool
  ${Boost_SYSTEM_LIBRARY}
  ${Boost_PROGRAM_OPTIONS_LIBRARY}
)

# mpc coordinator executable
add_executable(mpc-coord-phase2 mpc_coord.cpp)
target_link_libraries(mpc-coord-phase2 mpc-cli)

# mpc client executable
add_executable(mpc-client-phase2 mpc_client.cpp)
target_link_libraries(mpc-client-phase2 mpc-cli)

# mpc test utility
add_executable(mpc-test-phase2 test/mpc_test_cli.cpp)
target_link_libraries(mpc-test-phase2 mpc-cli)
