cmake_minimum_required(VERSION 3.5)
project(AES_GCM)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(SOURCE_FILES AES.cpp AES.h GCM.cpp GCM.h GCM.h)
add_executable(AES_GCM ${SOURCE_FILES})