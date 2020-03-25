# Build for mpc utilities
find_package( Boost REQUIRED COMPONENTS system filesystem program_options )
include_directories( ${Boost_INCLUDE_DIR} )

# Compile the pot-process utility (GROTH16 only)
if(${ZKSNARK} STREQUAL "GROTH16")
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
endif()
