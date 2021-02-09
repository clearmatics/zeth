# libsnark
OPTION(IS_LIBSNARK_PARENT OFF)
add_subdirectory(libsnark)

set_target_properties(snark PROPERTIES COMPILE_FLAGS
  "-Wno-error -Wno-unused-variable -Wno-unused-parameter -Wno-delete-non-virtual-dtor -Wno-sign-compare"
)

set_target_properties(ff PROPERTIES COMPILE_FLAGS
  "-Wno-error -Wno-unused-variable -Wno-unused-parameter"
)

set_target_properties(gtest PROPERTIES COMPILE_FLAGS
  "-Wno-error"
)

# get NUM_CPUS
include(ProcessorCount)
ProcessorCount(NUM_CPUS)
if(NOT NUM_CPUS EQUAL 0)
  set(MAKE_BUILD_FLAGS -j${NUM_CPUS})
endif()

# libsodium
set(LIBSODIUM_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/libsodium)
set(LIBSODIUM_CONFIGURE_CMD "CC=\"${CMAKE_C_COMPILER_LAUNCHER} ${CMAKE_C_COMPILER}\" CXX=\"${CMAKE_C_COMPILER_LAUNCHER} ${CMAKE_CXX_COMPILER}\" ./configure --prefix=<INSTALL_DIR> --enable-minimal --disable-shared --enable-static")

include(ExternalProject)
ExternalProject_Add(
  libsodium
  SOURCE_DIR ${LIBSODIUM_SOURCE_DIR}
  CONFIGURE_COMMAND cd ${LIBSODIUM_SOURCE_DIR} && DO_NOT_UPDATE_CONFIG_SCRIPTS=1 ./autogen.sh && eval ${LIBSODIUM_CONFIGURE_CMD}
  BUILD_COMMAND cd ${LIBSODIUM_SOURCE_DIR} && make ${MAKE_BUILD_FLAGS}
  INSTALL_COMMAND cd ${LIBSODIUM_SOURCE_DIR} && make install)
