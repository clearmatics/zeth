# Build for mpc utilities

find_package(Boost REQUIRED COMPONENTS system program_options)
include_directories(SYSTEM ${Boost_INCLUDE_DIR})

# Add the binary tree to the search path for include files
# so that we will find zethConfig.h
include_directories(${PROJECT_BINARY_DIR})

# Compile the pot-process utility (GROTH16 ALT-BN128 only)
if(${ZETH_SNARK} STREQUAL "GROTH16" AND ${ZETH_CURVE} STREQUAL "ALT_BN128")
  add_executable(
    pot-process
    pot_process/pot_process.cpp
  )
  target_link_libraries(
    pot-process

    zeth
    ${Boost_SYSTEM_LIBRARY}
    ${Boost_PROGRAM_OPTIONS_LIBRARY}
  )
  add_subdirectory(mpc_phase2)
else()
  message("Disabling MPC tools (only available in GROTH16 ALT-BN128 config)")
endif()
