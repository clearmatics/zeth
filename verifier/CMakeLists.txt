
find_package(Boost REQUIRED COMPONENTS system filesystem program_options)

file(GLOB_RECURSE VERIFIER_SOURCE **.?pp **.tcc)
add_executable(verifier ${VERIFIER_SOURCE})
target_include_directories(verifier PRIVATE SYSTEM ${Boost_INCLUDE_DIR})
target_link_libraries(
  verifier

  zeth
  ${Boost_SYSTEM_LIBRARY}
  ${Boost_FILESYSTEM_LIBRARY}
  ${Boost_PROGRAM_OPTIONS_LIBRARY}
  )
