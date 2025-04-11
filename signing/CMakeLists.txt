cmake_minimum_required(VERSION 3.20)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(signing)

# Include secp256k1 source files directly
file(GLOB_RECURSE SECP256K1_SOURCES
  modules/secp256k1/src/*.c
  # modules/secp256k1/src/modules/frost/*.c
)

# Add secp256k1 sources to your app
target_sources(app PRIVATE
  src/main.c
  ${SECP256K1_SOURCES}
)

# Include secp256k1 headers
zephyr_include_directories(
  modules/secp256k1/include
  modules/secp256k1/src/*.h
  # modules/secp256k1/src/modules/frost*.h
)

# Required compiler definitions for FROST
zephyr_compile_definitions(
    ENABLE_MODULE_FROST=1
    USE_BASIC_CONFIG=1
)

target_compile_options(app PRIVATE -Wno-unused-function)
