cmake_minimum_required(VERSION 3.9.0)
project(resolvetest)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall")

set(SOURCES resolvetest.cpp)

add_executable(resolvetest ${SOURCES})
set_property(TARGET resolvetest PROPERTY CXX_STANDARD 11)
