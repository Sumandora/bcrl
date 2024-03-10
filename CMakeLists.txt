cmake_minimum_required(VERSION 3.20)

include_guard()

project(bcrl)

file(GLOB_RECURSE BCRL_SOURCE_FILES "${PROJECT_SOURCE_DIR}/Source/*.cpp")
add_library(bcrl STATIC ${BCRL_SOURCE_FILES})
target_include_directories(bcrl PUBLIC "${PROJECT_SOURCE_DIR}/Include")
target_compile_options(bcrl PRIVATE "-Ofast")
target_compile_features(bcrl PRIVATE cxx_std_20)

include(FetchContent)

FetchContent_Declare(SignatureScanner
	GIT_REPOSITORY https://github.com/Sumandora/SignatureScanner
	GIT_PROGRESS TRUE
	GIT_TAG f9b8154)
FetchContent_MakeAvailable(SignatureScanner)
target_link_libraries(bcrl SignatureScanner)

FetchContent_Declare(LengthDisassembler
	GIT_REPOSITORY https://github.com/Jovvik/length-disassembler
	GIT_PROGRESS TRUE
	GIT_TAG 88fd89c)
FetchContent_MakeAvailable(LengthDisassembler)
target_link_libraries(bcrl length-disassembler)

if(PROJECT_IS_TOP_LEVEL)
	enable_testing()
	add_subdirectory("Example")
endif()
