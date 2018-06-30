include_directories(.)

#file(GLOB_RECURSE SOURCES
#    computation/*.hpp
#    computation/*.cpp
#    libsnark_helpers/*.hpp
#    libsnark_helpers/*.tcc
#    libsnark_helpers/*.cpp
#)

add_executable(main main.cpp computation/trusted_setup.hpp libsnark_helpers/libsnark_helpers.cpp)
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
