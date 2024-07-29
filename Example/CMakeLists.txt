add_library(ExampleTarget SHARED "Target/Target.cpp")

add_executable(BCRLExample "Source/Main.cpp")
add_subdirectory("${MemoryManager_SOURCE_DIR}/Modules/Linux" "LinuxMemoryManager")
target_link_libraries(BCRLExample PRIVATE ExampleTarget BCRL LinuxMemoryManager)
target_compile_features(BCRLExample PRIVATE cxx_std_23)
target_compile_options(BCRLExample PRIVATE "-O3")
add_test(NAME TestBCRLExample COMMAND $<TARGET_FILE:BCRLExample>)
