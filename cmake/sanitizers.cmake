# Compile targets with the specified sanitizer
#   - LeakSanitizer
#   - AddressSanitizer
#   - ThreadSanitizer
#   - UndefinedBehaviourSanitizer
#   - MemorySanitizer

# The sanitizers modify the program at compile-time to catch issues at runtime
set(
  SANITIZER
  ""
  CACHE
  STRING
  "Use sanitizers: one of Address, Leak, Thread, Memory, Undefined"
)

if(SANITIZER)
  if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
    message(WARNING "Compiling the code with sanitizers in non-debug mode"
      " is misleading and should be avoided"
      " (CMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE})")
  endif()

  if(SANITIZER STREQUAL "Address")
    # AddressSanitizer (detects addressability issues)
    # Note that: https://clang.llvm.org/docs/HardwareAssistedAddressSanitizerDesign.html is more efficient
    # See:
    # - https://github.com/google/sanitizers/wiki/AddressSanitizerFlags
    # - https://clang.llvm.org/docs/AddressSanitizer.html
    set(
      ASAN_OPTIONS
      symbolize=1
    )
    message("Set ASAN_OPTIONS to: ${ASAN_OPTIONS}")

    find_program(LLVM_SYMB_PATH llvm-symbolizer)
    set(
      ASAN_SYMBOLIZER_PATH
      ${LLVM_SYMB_PATH}
    )
    message("Set ASAN_SYMBOLIZER_PATH to: ${ASAN_SYMBOLIZER_PATH}")

    add_compile_options(-O1 -g -fsanitize=address -fno-omit-frame-pointer -fno-optimize-sibling-calls)
    add_link_options(-fsanitize=address)
  elseif(SANITIZER STREQUAL "Leak")
    # LeakSanitizer (detects memory leaks)
    # See: https://clang.llvm.org/docs/LeakSanitizer.html
    set(
      ASAN_OPTIONS
      detect_leaks=1
    )
    message("Set ASAN_OPTIONS to: ${ASAN_OPTIONS}")

    add_compile_options(-g -fsanitize=leak)
    add_link_options(-fsanitize=leak)
  elseif (SANITIZER STREQUAL "Thread")
    # ThreadSanitizer (detects data races and deadlocks)
    add_compile_options(-O1 -g -fsanitize=thread)
    add_link_options(-fsanitize=thread)
  elseif (SANITIZER STREQUAL "Memory")
    # MemorySanitizer (detects use of uninitialized memory)
    # See:
    #  - https://clang.llvm.org/docs/MemorySanitizer.html
    find_program(LLVM_SYMB_PATH llvm-symbolizer)
    set(
      MSAN_SYMBOLIZER_PATH
      ${LLVM_SYMB_PATH}
    )
    message("Set MSAN_SYMBOLIZER_PATH to: ${ASAN_SYMBOLIZER_PATH}")

    add_compile_options(-O1 -g -fsanitize=memory -fsanitize-memory-track-origins -fno-omit-frame-pointer -fno-optimize-sibling-calls)
    add_link_options(-fsanitize=memory)
  elseif (SANITIZER STREQUAL "Undefined")
    # UndefinedBehaviorSanitizer (detects undefined behaviors)
    # See:
    #  - https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html
    set(
      UBSAN_OPTIONS
      print_stacktrace=1
    )
    message("Set UBSAN_OPTIONS to: ${UBSAN_OPTIONS}")

    add_compile_options(-O1 -g -fsanitize=undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=undefined)
  else()
      message(FATAL_ERROR "Unknown sanitizer. Aborting...")
  endif()
endif()
