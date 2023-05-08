cmake_minimum_required(VERSION 3.20)

project(factorio-large-pages LANGUAGES CXX C)

find_package(TBB REQUIRED)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)
set(CMAKE_VISIBILITY_INLINES_HIDDEN 1)

add_executable(launcher main.cpp)


add_library(proxy SHARED proxy.cpp)
target_link_libraries(proxy TBB::tbb TBB::tbbmalloc TBB::tbbmalloc)

install(TARGETS launcher DESTINATION ${CMAKE_INSTALL_PREFIX})
install(TARGETS proxy DESTINATION ${CMAKE_INSTALL_PREFIX})
