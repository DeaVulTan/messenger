cmake_minimum_required(VERSION 2.8 FATAL_ERROR)

add_subdirectory(../third_party/gtest/googletest googletest)

include_directories(
    ../third_party/gtest/googletest/include
    /usr/include
    /usr/local/include
    ../
)
FIND_LIBRARY(SODIUM sodium /usr/lib /usr/local/lib)
FIND_LIBRARY(CRYPTOPP cryptopp /usr/lib /usr/local/lib)
FIND_LIBRARY(CURL curl /usr/lib /usr/local/lib)
FIND_LIBRARY(STRONGVELOPE strongvelope_cpp ../ ../build/)
FIND_LIBRARY(MEGA mega ../ ../build/)

add_definitions(-D__TEST)

if(NOT WIN32)
     add_definitions(-Wall -std=c++11 -fexceptions -pthread)
endif()

set(TEST_SRCS
    tests.cpp
)

add_executable(strongvelope_tests ${TEST_SRCS})

target_link_libraries(strongvelope_tests ${SODIUM} ${CRYPTOPP} ${CURL} ${STRONGVELOPE} ${MEGA} gtest gtest_main)

ADD_CUSTOM_TARGET(tests
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/strongvelope_tests
)