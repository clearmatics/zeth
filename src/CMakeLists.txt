include_directories(.)

file(GLOB_RECURSE SOURCES
    prover/computation.tcc
    prover/prover.tcc
    libsnark_helpers/libsnark_helpers.cpp
    sha256/sha256_ethereum.cpp
    cli/setupCmd.cpp
    cli/proveCmd.cpp
    cli/mainCmd.cpp
)

add_executable(
    main 

    main.cpp
    ${SOURCES}
)

target_link_libraries(
  main

  snark
)

target_include_directories(
  main

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)
