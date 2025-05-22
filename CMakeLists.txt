cmake_minimum_required(VERSION 3.20)

include_guard()

project(BCRL)

add_library(BCRL INTERFACE)
target_include_directories(BCRL INTERFACE "${PROJECT_SOURCE_DIR}/Include")
target_compile_features(BCRL INTERFACE cxx_std_23)

include(FetchContent)

if(NOT TARGET SignatureScanner)
	FetchContent_Declare(
		SignatureScanner
		GIT_REPOSITORY https://github.com/Sumandora/SignatureScanner
		GIT_PROGRESS TRUE
		GIT_TAG 3.3)
	FetchContent_MakeAvailable(SignatureScanner)
endif()
target_link_libraries(BCRL INTERFACE SignatureScanner)

if(NOT TARGET LengthDisassembler)
	FetchContent_Declare(
		LengthDisassembler
		GIT_REPOSITORY https://github.com/Sumandora/LengthDisassembler
		GIT_PROGRESS TRUE
		GIT_TAG 1.0.1)
	FetchContent_MakeAvailable(LengthDisassembler)
endif()
target_link_libraries(BCRL INTERFACE LengthDisassembler)

if(NOT TARGET MemoryManager)
	FetchContent_Declare(
		MemoryManager
		GIT_REPOSITORY https://github.com/Sumandora/MemoryManager
		GIT_PROGRESS TRUE
		GIT_TAG 2.6)
	FetchContent_MakeAvailable(MemoryManager)
endif()
target_link_libraries(BCRL INTERFACE MemoryManager)

if(PROJECT_IS_TOP_LEVEL)
	enable_testing()
	add_subdirectory("Example")
endif()
