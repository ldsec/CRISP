cmake_minimum_required(VERSION 3.15)
project(HEAAN)

set(CMAKE_CXX_STANDARD 14)

include_directories(lib)
include_directories(run)
include_directories(src)
include_directories(NTL)

add_executable(HEAAN
        run/runMPCmult.cpp
)
