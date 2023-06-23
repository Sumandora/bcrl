cmake_minimum_required(VERSION 3.20)
project(bcrl)

set(CMAKE_CXX_STANDARD 23)

set(CMAKE_CXX_FLAGS "-ggdb3")
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

add_executable(bcrl
    Source/AddressableMemory.cpp
    Source/SafePointer/SafePointer.cpp
    Source/SafePointer/Signatures.cpp
    Source/SafePointer/X86.cpp
    Source/Session/AdvancedFlow.cpp
    Source/Session/DownPassers.cpp
    Source/Session/Finalizers.cpp
    Source/Session/Openers.cpp
    
    Example/Main.cpp)
target_include_directories(bcrl PRIVATE Include)

target_include_directories(bcrl PRIVATE Dependencies/length-disassembler)
file(GLOB LDE_SOURCE_FILES "${CMAKE_SOURCE_DIR}/Dependencies/length-disassembler/*.cpp")
target_sources(bcrl PRIVATE ${LDE_SOURCE_FILES})

# When using this you won't have the length disassembler to step through instructions
#target_compile_definitions(bcrl PRIVATE BCLR_DISABLE_LDE)

target_include_directories(bcrl PRIVATE Dependencies/SignatureScanner/include)
file(GLOB SIGNATURESCANNER_SOURCE_FILES "${CMAKE_SOURCE_DIR}/Dependencies/SignatureScanner/Source/*.cpp")
target_sources(bcrl PRIVATE ${SIGNATURESCANNER_SOURCE_FILES})