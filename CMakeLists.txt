cmake_minimum_required(VERSION 3.20)

include_guard()

project(BCRL)

add_library(BCRL INTERFACE)
target_include_directories(BCRL INTERFACE "${PROJECT_SOURCE_DIR}/Include")
target_compile_features(BCRL INTERFACE cxx_std_23)

include(FetchContent)

FetchContent_Declare(SignatureScanner
	GIT_REPOSITORY https://github.com/Sumandora/SignatureScanner
	GIT_PROGRESS TRUE
	GIT_TAG 2.1)
FetchContent_MakeAvailable(SignatureScanner)
add_subdirectory("${SignatureScanner_SOURCE_DIR}/Modules/Pattern" "PatternSignatures")
target_link_libraries(BCRL INTERFACE SignatureScanner PatternSignature)

FetchContent_Declare(LengthDisassembler
	GIT_REPOSITORY https://github.com/Jovvik/length-disassembler
	GIT_PROGRESS TRUE
	GIT_TAG 88fd89c)
FetchContent_MakeAvailable(LengthDisassembler)
target_link_libraries(BCRL INTERFACE length-disassembler)

FetchContent_Declare(MemoryManager
		GIT_REPOSITORY https://github.com/Sumandora/MemoryManager
		GIT_PROGRESS TRUE
		GIT_TAG 1.0)
FetchContent_MakeAvailable(MemoryManager)
target_link_libraries(BCRL INTERFACE MemoryManager)

if(PROJECT_IS_TOP_LEVEL)
	enable_testing()
	add_subdirectory("Example")
endif()
