cmake_minimum_required(VERSION 3.15)
project(BinGuardian)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(BinGuardian
    src/main.cpp
    src/Scanner.cpp
    src/Remediation.cpp
    src/Utils.cpp
)

target_link_libraries(BinGuardian PRIVATE
    psapi
    wintrust
    crypt32
)

add_executable(compare src/compare.cpp)