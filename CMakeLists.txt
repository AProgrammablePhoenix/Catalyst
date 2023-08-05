cmake_minimum_required(VERSION 3.22)

project(catalyst)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

file(COPY
    "catalyst.hpp"
    DESTINATION ${CMAKE_BINARY_DIR}/include
)

add_library(sha3 STATIC
    "sha3/sha3_internal.cpp"
    "sha3/sha3.cpp"
)

add_library(devcatalyst STATIC
    "devcatalyst/catalyst_helper.cpp"
    "devcatalyst/catalyst_constants.cpp"
    "devcatalyst/catalyst_sigmas.cpp"
    "devcatalyst/catalyst_sbox.cpp"
    "devcatalyst/catalyst_extend.cpp"
    "devcatalyst/catalyst_xor.cpp"
    "devcatalyst/catalyst_stages.cpp"
)

add_executable(catalyst
    "commandline_args.cpp"
    "catalyst.cpp"
)

target_compile_features(sha3 PUBLIC cxx_std_23)
target_compile_features(devcatalyst PUBLIC cxx_std_23)
target_compile_features(catalyst PUBLIC cxx_std_23)

target_link_libraries(devcatalyst sha3)
target_link_libraries(catalyst devcatalyst)

include(GNUInstallDirs)
set(CATALYST_HEADERS_INSTALL_DIR ${CMAKE_INSTALL_FULL_DATADIR}/catalyst)

install(TARGETS
    devcatalyst catalyst
)

install(FILES "catalyst.hpp"
    DESTINATION ${CATALYST_HEADERS_INSTALL_DIR}
)