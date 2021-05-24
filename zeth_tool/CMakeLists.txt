
find_package(Boost REQUIRED COMPONENTS system filesystem program_options)

file(GLOB_RECURSE ZETH_TOOL_SOURCE **.?pp **.tcc)
add_executable(zeth-tool ${ZETH_TOOL_SOURCE})
target_include_directories(zeth-tool PRIVATE SYSTEM ${Boost_INCLUDE_DIR})
target_link_libraries(
  zeth-tool

  tool
  zeth
  ${Boost_SYSTEM_LIBRARY}
  ${Boost_FILESYSTEM_LIBRARY}
  ${Boost_PROGRAM_OPTIONS_LIBRARY}
  )
