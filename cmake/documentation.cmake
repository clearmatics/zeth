# Generate code documentation for the project.
# We use Doxygen.
# TODO: Consider using: https://codedocs.xyz/
#
# The following is adapted from:
# https://vicrucann.github.io/tutorials/quick-cmake-doxygen/

# Check if Doxygen is installed
find_package(Doxygen)
if(DOXYGEN_FOUND)
  # Set input and output files
  set(DOXYGEN_IN ${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.in)
  set(DOXYGEN_OUT ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile)

  # Request to configure the file
  configure_file(${DOXYGEN_IN} ${DOXYGEN_OUT} @ONLY)
  message("Doxygen build started")

  # The option ALL allows to build the docs together with the application
  add_custom_target(
    doc_doxygen
    ALL
    COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYGEN_OUT}
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    COMMENT "Generating API documentation with Doxygen"
    VERBATIM
  )
else(DOXYGEN_FOUND)
    message("You need to install Doxygen to generate the documentation")
endif(DOXYGEN_FOUND)
