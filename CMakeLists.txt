cmake_minimum_required(VERSION 3.0)
project(backtrace)

set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 11)

add_library(backtrace
        backtrace.c
        backtrace.h
        Elf.h
        Elf.cpp)
target_compile_definitions(backtrace PUBLIC _GNU_SOURCE)
target_include_directories(backtrace PUBLIC .)
target_link_libraries(backtrace dl)

add_executable(backtrace_test main.c)
# target_link_options(backtrace_test PRIVATE -static)
target_link_libraries(backtrace_test backtrace)
