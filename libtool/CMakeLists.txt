include_directories(.)

find_package(Boost REQUIRED COMPONENTS program_options)
include_directories(${Boost_INCLUDE_DIR})

file(GLOB_RECURSE LIBTOOL_SOURCE **.?pp **.tcc)

add_library(tool ${LIBTOOL_SOURCE})
target_include_directories(tool PUBLIC ..)
target_link_libraries(tool ${Boost_PROGRAM_OPTIONS_LIBRARY})
