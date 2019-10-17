OPTION(IS_LIBSNARK_PARENT OFF)
add_subdirectory(libsnark)

set_target_properties(snark PROPERTIES COMPILE_FLAGS
  "-Wno-unused-variable -Wno-unused-parameter -Wno-delete-non-virtual-dtor -Wno-sign-compare"
)

set_target_properties(ff PROPERTIES COMPILE_FLAGS
  "-Wno-unused-variable -Wno-unused-parameter"
)

add_library(blake2 blake2/sse/blake2b.c)
target_include_directories(blake2 PUBLIC blake2/sse)

file(GLOB_RECURSE SODIUM_SOURCE libsodium/**.c)
add_library(sodium ${SODIUM_SOURCE})
target_include_directories(
  sodium

  PUBLIC
  libsodium/include

  PRIVATE
  libsodium/include/sodium
  libsodium/crypto_stream/chacha20
  )
target_compile_definitions(sodium PRIVATE DEV_MODE=1 CONFIGURED=1)
