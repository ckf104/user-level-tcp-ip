cmake_minimum_required(VERSION 3.0.0)
project(src VERSION 0.1.0)

set(CMAKE_CXX_STANDARD 17)

#include(CTest)
#enable_testing()

add_library(src SHARED packetio.cpp device.cpp arp.cpp iplayer.cpp general.cpp sock.cpp tcplayer.cpp tcp_timer.cpp)
target_link_libraries(src pcap)
target_link_libraries(src pthread)
#add_compile_definitions(src PRIVATE debug4)
#add_compile_definitions(src PRIVATE block_close)
set(CMAKE_BUILD_TYPE "Release")
set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
#include(CPack)
