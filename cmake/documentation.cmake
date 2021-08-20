# Generate the Doxygen code documentation for the project.
#
# TODO: Consider using: https://codedocs.xyz/ at some point
#
# The following is adapted from:
# https://vicrucann.github.io/tutorials/quick-cmake-doxygen/

# Check if Doxygen is installed
find_package(Doxygen)
if(NOT DOXYGEN_FOUND)
  message(FATAL_ERROR "You need to install Doxygen to generate"
    " the documentation. Aborting...")
endif()

# Set input and output files
set(DOXYGEN_IN ${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.in)
set(DOXYGEN_OUT ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile)

# Request to configure the file
configure_file(${DOXYGEN_IN} ${DOXYGEN_OUT} @ONLY)
message("Doxygen build started")

# The option ALL allows to build the docs together with the application
add_custom_target(
  build_docs
  ALL
  COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYGEN_OUT}
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  COMMENT "Generating API documentation with Doxygen"
  VERBATIM
)

find_program(XDG_OPEN xdg-open)
if(NOT XDG_OPEN)
  set(XDG_OPEN cmake -E echo Documentation generated. Open )
endif()

add_custom_target(
  docs
  COMMAND ${XDG_OPEN} ${CMAKE_CURRENT_BINARY_DIR}/docs/html/index.html
  DEPENDS build_docs
)
