include_directories(.)

#file(GLOB_RECURSE SOURCES
#    computation/*.hpp
#    computation/*.cpp
#    libsnark_helpers/*.hpp
#    libsnark_helpers/*.tcc
#    libsnark_helpers/*.cpp
#)

add_executable(main main.cpp prover/computation.tcc prover/prover.tcc libsnark_helpers/libsnark_helpers.cpp sha256/sha256_ethereum.cpp)
#${SOURCES}

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
