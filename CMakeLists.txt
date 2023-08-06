cmake_minimum_required(VERSION 3.20)
project(bcrl)

set(CMAKE_CXX_STANDARD 23)

set(CMAKE_CXX_FLAGS "-ggdb3")
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

add_library(bcrl STATIC)
file(GLOB_RECURSE BCRL_SOURCE_FILES "${CMAKE_SOURCE_DIR}/Source/*.cpp")
target_sources(bcrl PRIVATE ${BCRL_SOURCE_FILES})
target_include_directories(bcrl PUBLIC Include)

add_subdirectory(Dependencies/SignatureScanner)
target_link_libraries(bcrl PRIVATE SignatureScanner)

add_subdirectory(Dependencies/length-disassembler)
target_link_libraries(bcrl PRIVATE length-disassembler)

# When using this you won't have the length disassembler to step through instructions
#target_compile_definitions(bcrl PUBLIC BCLR_DISABLE_LDE)

target_compile_definitions(bcrl PRIVATE SIGNATURESCANNER_ENABLE_IDA_SEARCH)
target_compile_definitions(bcrl PRIVATE SIGNATURESCANNER_ENABLE_STRING_SEARCH)
target_compile_definitions(bcrl PRIVATE SIGNATURESCANNER_ENABLE_XREF_SEARCH)

add_executable(bcrlExample Example/Main.cpp)
target_link_libraries(bcrlExample PRIVATE bcrl)

enable_testing()
add_test(NAME bcrlExample COMMAND $<TARGET_FILE:bcrlExample>)
