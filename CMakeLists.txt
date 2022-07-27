cmake_minimum_required(VERSION 3.21)
project(palantir C)

set(CMAKE_C_STANDARD 23)

add_executable(palantir main.c dns.h dns.c)
