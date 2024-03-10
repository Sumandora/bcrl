cmake_minimum_required(VERSION 3.20)

include_guard()

project(bcrlCWrapper)

add_library(bcrlCWrapper STATIC "${PROJECT_SOURCE_DIR}/Source/BCRLWrapper.cpp")
target_include_directories(bcrlCWrapper PUBLIC "${PROJECT_SOURCE_DIR}/Include")
target_compile_options(bcrlCWrapper PRIVATE "-Ofast" "-Wno-conversion-null")
target_compile_features(bcrlCWrapper PRIVATE cxx_std_20)

target_link_libraries(bcrlCWrapper PUBLIC bcrl)
