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

# Enable Boost for program_options
FIND_PACKAGE( Boost REQUIRED COMPONENTS system filesystem )
INCLUDE_DIRECTORIES( ${Boost_INCLUDE_DIR} )

add_executable(
    zeth

    main.cpp
    ${SOURCES}
)

target_link_libraries(
    zeth

    LINK_PUBLIC # See: https://stackoverflow.com/questions/21125362/cmake-link-private-and-its-inheritance
    snark # Libsnark library
    ${Boost_SYSTEM_LIBRARY}
    ${Boost_FILESYSTEM_LIBRARY}
)

target_include_directories(
    zeth

    PUBLIC
    ${DEPENDS_DIR}/libsnark
    ${DEPENDS_DIR}/libsnark/depends/libfqfft
)
