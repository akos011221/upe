cmake_minimum_required(VERSION 3.16)
project(upe C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

add_executable(upe
  src/main.c
  src/log.c
  src/rx_pcap.c
  src/parser.c
  src/rule_table.c
  src/worker.c
  src/pktbuf.c
  src/tx_afpacket.c
  src/ring.c
  src/arp_table.c
  src/ndp_table.c
  src/affinity.c
  src/rule_config.c
)

target_include_directories(upe PRIVATE include)

target_link_libraries(upe pcap)

target_compile_options(upe PRIVATE
  -Wall
  -Wextra
  -Wpedantic
  -Wconversion
  -Wsign-conversion
  -Wshadow
  -Wformat=2
  -Wundef
  -Werror
)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  target_compile_options(upe PRIVATE -O0 -g3)
elseif(CMAKE_BUILD_TYPE STREQUAL "Release")
  target_compile_options(upe PRIVATE -O3)
endif()

# -- Testing --
enable_testing()

add_executable(test_suite
    tests/test_suite.c
    src/parser.c
    src/pktbuf.c
    src/ring.c
    src/rule_table.c
    src/rule_config.c
    src/log.c
    src/arp_table.c
    src/ndp_table.c
    src/affinity.c
)
target_include_directories(test_suite PRIVATE include)
# Simulating ARM/RISC-V crashes on x86 with Alignment Sanitizer
target_compile_options(test_suite PRIVATE -g -fsanitize=alignment)
target_link_options(test_suite PRIVATE -fsanitize=alignment)
target_link_libraries(test_suite pthread)

add_test(NAME UPE_Unit_Tests COMMAND test_suite)

# -- Benchmarks --
add_executable(benchmark_pktbuf tests/benchmark_pktbuf.c src/pktbuf.c src/benchmark_test.c src/log.c)
target_include_directories(benchmark_pktbuf PRIVATE include)
target_link_libraries(benchmark_pktbuf pthread m)

add_executable(benchmark_throughput tests/benchmark_throughput.c src/pktbuf.c src/ring.c src/rule_table.c src/worker.c src/parser.c src/log.c src/arp_table.c src/ndp_table.c src/affinity.c src/benchmark_test.c src/log.c)
target_include_directories(benchmark_throughput PRIVATE include)
target_link_libraries(benchmark_throughput pthread m)
