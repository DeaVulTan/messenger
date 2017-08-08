cmake_minimum_required(VERSION 2.8 FATAL_ERROR)
set(CMAKE_LEGACY_CYGWIN_WIN32 0)

project("strongvelope_cpp")
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}")

find_package(libsodium)
find_package(mega)

option(optStrongvelopeTests "Build strongvelope tests" OFF)
option(optStrongvelopeBuildShared "Build strongvelope as shared lib" ON)

add_definitions(
    -D__HAS_LIBSODIUM -D__USE_LIBSODIUM_HASH -D__USE_LIBSODIUM_AES ${LIBMEGA_DEFINES}
)

set(SRCS src/strongvelope.cpp)

set(STRONGVELOPE_INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/src")
include_directories(${LIBMEGA_INCLUDE_DIRS})

if(NOT WIN32)
     add_definitions(-Wall -std=c++11 -fvisibility=default -fexceptions -pthread)
endif()

if (optStrongvelopeBuildShared)
    add_library(strongvelope_cpp SHARED ${SRCS})
else()
    add_library(strongvelope_cpp ${SRCS})
endif()

target_link_libraries(strongvelope_cpp ${LIBSODIUM_LIBRARIES} ${LIBMEGA_LIBRARIES})

find_package(Doxygen)

#if(DOXYGEN_FOUND)
#    configure_file(
#        ${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.in
#        ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile @ONLY
#    )
#    add_custom_target(doc ${DOXYGEN_EXECUTABLE}
#        ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
#        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
#        COMMENT "Generating strongvelope_cpp documentation" VERBATIM
#    )

#endif(DOXYGEN_FOUND)

if (optStrongvelopeTests)
    add_subdirectory(tests)
endif()
