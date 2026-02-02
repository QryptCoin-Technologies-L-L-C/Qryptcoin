cmake_minimum_required(VERSION 3.22)

project(qryptcoin-node VERSION 1.0.1 LANGUAGES C CXX)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)
  message(FATAL_ERROR "In-source builds are not supported. Run CMake with -B <build_dir>.")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(CTest)

option(QRY_BUILD_BINARIES "Build node/CLI executables" ON)
option(BUILD_FUZZING "Build libFuzzer fuzz targets (Clang)" OFF)

if(WIN32)
  add_compile_definitions(NOMINMAX WIN32_LEAN_AND_MEAN)
endif()

if(MSVC)
  # Use a consistent runtime library across all targets to avoid link-time
  # runtime conflicts (e.g., LIBCMT vs MSVCRT).
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL" CACHE STRING "" FORCE)
endif()

set(GENERATED_INCLUDE_DIR ${CMAKE_BINARY_DIR}/generated)
file(MAKE_DIRECTORY ${GENERATED_INCLUDE_DIR}/config)

# --- Vendored dependencies (no network required) ----------------------------

# liboqs (ML-KEM + ML-DSA)
set(OQS_BUILD_ONLY_LIB ON CACHE BOOL "" FORCE)
# Minimize liboqs to the algorithms required by the node.
# This reduces build time and audit surface area while keeping builds deterministic.
set(OQS_MINIMAL_BUILD "KEM_ml_kem_768;SIG_ml_dsa_65" CACHE STRING "" FORCE)
set(OQS_USE_OPENSSL OFF CACHE BOOL "" FORCE)
set(OQS_USE_SHA3_KECCAK OFF CACHE BOOL "" FORCE)
set(ENABLE_SHARED OFF CACHE BOOL "" FORCE)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(OQS_DIST_BUILD OFF CACHE BOOL "" FORCE)
add_subdirectory(vendor/liboqs EXCLUDE_FROM_ALL)

# Argon2 (wallet KDF)
set(ARGON2_SOURCES
  vendor/argon2/src/argon2.c
  vendor/argon2/src/core.c
  vendor/argon2/src/encoding.c
  vendor/argon2/src/ref.c
  vendor/argon2/src/thread.c
  vendor/argon2/src/blake2/blake2b.c
)
add_library(argon2 STATIC ${ARGON2_SOURCES})
target_include_directories(argon2 PUBLIC ${CMAKE_SOURCE_DIR}/vendor/argon2/include)
target_compile_features(argon2 PRIVATE c_std_99)
target_compile_definitions(argon2 PRIVATE ARGON2_NO_THREADS=0)

# Dilithium3 reference (ML-DSA) object library
set(DILITHIUM_REF_SOURCES
  third_party/dilithium/ref/fips202.c
  third_party/dilithium/ref/ntt.c
  third_party/dilithium/ref/packing.c
  third_party/dilithium/ref/poly.c
  third_party/dilithium/ref/polyvec.c
  third_party/dilithium/ref/reduce.c
  third_party/dilithium/ref/rounding.c
  third_party/dilithium/ref/sign.c
  third_party/dilithium/ref/symmetric-shake.c
)
add_library(dilithium_ref_objects OBJECT ${DILITHIUM_REF_SOURCES})
target_include_directories(dilithium_ref_objects PUBLIC ${CMAKE_SOURCE_DIR}/third_party/dilithium/ref)
target_compile_features(dilithium_ref_objects PRIVATE c_std_99)
target_compile_definitions(dilithium_ref_objects PUBLIC DILITHIUM_MODE=3)

# Build metadata header (non-consensus)
set(GIT_DESCRIBE "not-available")
find_package(Git QUIET)
if(Git_FOUND)
  execute_process(
    COMMAND ${GIT_EXECUTABLE} describe --tags --always --dirty
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    OUTPUT_VARIABLE _git_describe
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
    RESULT_VARIABLE _git_result)
  if(_git_result EQUAL 0 AND NOT _git_describe STREQUAL "")
    set(GIT_DESCRIBE "${_git_describe}")
  endif()
endif()

configure_file(
  ${CMAKE_SOURCE_DIR}/src/node/config/build_info.hpp.in
  ${GENERATED_INCLUDE_DIR}/config/build_info.hpp
  @ONLY
)

# --- Core library -----------------------------------------------------------

set(QRY_CORE_SOURCES
  src/consensus/block_hash.cpp
  src/consensus/block_validator.cpp
  src/consensus/block_weight.cpp
  src/consensus/monetary.cpp
  src/consensus/params.cpp
  src/consensus/pow.cpp
  src/consensus/revealed_pubkeys.cpp
  src/consensus/sighash.cpp
  src/consensus/sparse_merkle_tree.cpp
  src/consensus/tx_validator.cpp
  src/consensus/utxo.cpp
  src/consensus/versionbits.cpp

  src/node/config/network.cpp

  src/crypto/bech32.cpp
  src/crypto/mnemonic.cpp
  src/crypto/payment_code.cpp
  src/crypto/payment_code_short.cpp
  src/crypto/crypto_suite.cpp
  src/crypto/deterministic_rng.cpp
  src/crypto/dilithium_randombytes.cpp
  src/crypto/hash.cpp
  src/crypto/p2qh_address.cpp
  src/crypto/p2qh_descriptor.cpp
  src/crypto/pq_engine.cpp
  src/crypto/stealth_address.cpp

  src/tx/primitives/merkle.cpp
  src/tx/primitives/serialize.cpp
  src/tx/primitives/txid.cpp

  src/tx/policy/fee_estimator.cpp
  src/tx/policy/standardness.cpp

  src/tx/script/l2_anchor.cpp
  src/tx/script/p2qh.cpp
  src/tx/script/script.cpp

  src/node/block_builder.cpp
  src/node/block_sync.cpp
  src/node/chain_state.cpp
  src/node/mining_extranonce.cpp

  src/node/storage/block_store.cpp
  src/node/storage/revealed_pubkeys_snapshot.cpp
  src/node/storage/tx_fee_snapshot.cpp
  src/node/storage/utxo_snapshot.cpp

  src/net/addr_manager.cpp
  src/net/channel.cpp
  src/net/dns_seeds.cpp
  src/net/encrypted_channel.cpp
  src/net/handshake.cpp
  src/net/messages.cpp
  src/net/peer_manager.cpp
  src/net/peer_session.cpp
  src/net/socket.cpp
  src/net/time_adjuster.cpp
  src/net/transport_auth.cpp
  src/net/upnp.cpp

  src/node/rpc/http_server.cpp
  src/node/rpc/server.cpp

  src/wallet/hd_wallet.cpp
  src/wallet/wallet_context.cpp

  src/util/aead.cpp
  src/util/base64.cpp
  src/util/argon2_kdf.cpp
  src/util/atomic_file.cpp
  src/util/csprng.cpp
  src/util/eta.cpp
  src/util/hex.cpp
  src/util/pbkdf2.cpp
  src/util/secure_wipe.cpp
  src/util/system.cpp
)

add_library(qryptcore STATIC ${QRY_CORE_SOURCES})
target_compile_features(qryptcore PUBLIC cxx_std_20)
target_sources(qryptcore PRIVATE $<TARGET_OBJECTS:dilithium_ref_objects>)
target_link_libraries(qryptcore PUBLIC oqs argon2)

target_include_directories(qryptcore
  PUBLIC
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/node
    ${CMAKE_SOURCE_DIR}/src/tx
    ${CMAKE_SOURCE_DIR}/third_party
    ${GENERATED_INCLUDE_DIR}
    ${CMAKE_SOURCE_DIR}/third_party/dilithium/ref
    ${CMAKE_SOURCE_DIR}/vendor/liboqs/src
    ${CMAKE_SOURCE_DIR}/vendor/liboqs/src/common
    ${CMAKE_BINARY_DIR}/vendor/liboqs/include
)

if(MSVC)
  target_compile_options(qryptcore PRIVATE /W4 /permissive-)
else()
  target_compile_options(qryptcore PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(WIN32)
  target_link_libraries(qryptcore PUBLIC ws2_32 bcrypt)
endif()

# --- Node daemon ------------------------------------------------------------

if(QRY_BUILD_BINARIES)
  add_executable(qryptd src/node/qryptd.cpp)
  target_link_libraries(qryptd PRIVATE qryptcore)
  if(WIN32)
    target_link_libraries(qryptd PRIVATE Advapi32)
  endif()

# --- CLI tools --------------------------------------------------------------

  add_executable(qrypt-cli tools/qrypt_cli.cpp)
  target_link_libraries(qrypt-cli PRIVATE qryptcore)
  if(WIN32)
    target_link_libraries(qrypt-cli PRIVATE Advapi32)
  endif()

  add_executable(qrypt-payresolver tools/qrypt_payresolver.cpp)
  target_link_libraries(qrypt-payresolver PRIVATE qryptcore)
  if(WIN32)
    target_link_libraries(qrypt-payresolver PRIVATE Advapi32)
  endif()
endif()

# --- Tests ------------------------------------------------------------------

if(BUILD_TESTING)
  file(GLOB_RECURSE QRY_TEST_SOURCES CONFIGURE_DEPENDS
    tests/unit/*.cpp
    tests/integration/*.cpp
    tests/node/*.cpp
  )
  foreach(test_src IN LISTS QRY_TEST_SOURCES)
    file(RELATIVE_PATH rel_src ${CMAKE_SOURCE_DIR}/tests ${test_src})
    string(REPLACE "/" "_" rel_name ${rel_src})
    string(REPLACE "\\" "_" rel_name ${rel_name})
    string(REPLACE ".cpp" "" rel_name ${rel_name})
    set(target_name "qrypt_${rel_name}")
    add_executable(${target_name} ${test_src})
    target_link_libraries(${target_name} PRIVATE qryptcore)
    target_include_directories(${target_name} PRIVATE ${CMAKE_SOURCE_DIR})
    add_test(NAME ${target_name} COMMAND ${target_name})
  endforeach()
endif()

# --- Fuzzing ----------------------------------------------------------------

if(BUILD_FUZZING)
  if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "BUILD_FUZZING requires Clang (libFuzzer).")
  endif()
  if(MSVC)
    message(FATAL_ERROR "BUILD_FUZZING is currently supported on Clang-based toolchains only.")
  endif()

  # Instrument QryptCoin code for coverage-guided fuzzing. Vendor dependencies
  # are left untouched to keep the fuzz build surface minimal.
  target_compile_options(qryptcore PRIVATE -fsanitize=fuzzer-no-link,address,undefined -fno-omit-frame-pointer)

  file(GLOB_RECURSE QRY_FUZZ_SOURCES CONFIGURE_DEPENDS
    tests/fuzz/*.cpp
  )
  foreach(fuzz_src IN LISTS QRY_FUZZ_SOURCES)
    file(RELATIVE_PATH rel_src ${CMAKE_SOURCE_DIR}/tests/fuzz ${fuzz_src})
    string(REPLACE "/" "_" rel_name ${rel_src})
    string(REPLACE "\\" "_" rel_name ${rel_name})
    string(REPLACE ".cpp" "" rel_name ${rel_name})
    set(target_name "qrypt_fuzz_${rel_name}")
    add_executable(${target_name} ${fuzz_src})
    target_link_libraries(${target_name} PRIVATE qryptcore)
    target_include_directories(${target_name} PRIVATE ${CMAKE_SOURCE_DIR})
    target_compile_options(${target_name} PRIVATE -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer)
    target_link_options(${target_name} PRIVATE -fsanitize=fuzzer,address,undefined)
  endforeach()
endif()

# --- Install / Packaging ----------------------------------------------------

if(QRY_BUILD_BINARIES)
  install(TARGETS qryptd qrypt-cli qrypt-payresolver
          RUNTIME DESTINATION bin)
endif()

set(CPACK_PACKAGE_NAME "qryptcoin-core")
set(CPACK_PACKAGE_VENDOR "QryptCoin Technologies LLC")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "QryptCoin node daemon and CLI tooling")
set(CPACK_PACKAGE_VERSION_MAJOR ${PROJECT_VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${PROJECT_VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${PROJECT_VERSION_PATCH})
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_SOURCE_DIR}/LICENSE")

# Default to a portable tarball; DEB can be requested via: cpack -G DEB
set(CPACK_GENERATOR "TGZ")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "support@qryptcoin.org")

include(CPack)
