add_library(ExampleTarget SHARED "Target/Target.cpp")

add_executable(BCRLExample "Source/Main.cpp")
add_subdirectory("${MemoryManager_SOURCE_DIR}/Modules/Local" "LocalMemoryManager")
add_subdirectory("../Modules/X86" "BCRLx86")
target_link_libraries(BCRLExample PRIVATE ExampleTarget BCRL BCRLx86 LocalMemoryManager)
target_compile_features(BCRLExample PRIVATE cxx_std_23)
add_test(NAME TestBCRLExample COMMAND $<TARGET_FILE:BCRLExample>)
