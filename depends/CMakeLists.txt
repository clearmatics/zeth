OPTION(IS_LIBSNARK_PARENT OFF)
add_subdirectory(libsnark)

set_target_properties(snark PROPERTIES COMPILE_FLAGS
  "-Wno-unused-variable -Wno-unused-parameter -Wno-delete-non-virtual-dtor -Wno-sign-compare"
)

set_target_properties(ff PROPERTIES COMPILE_FLAGS
  "-Wno-unused-variable -Wno-unused-parameter"
)
