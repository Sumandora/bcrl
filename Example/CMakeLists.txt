add_library(ExampleTarget SHARED "Target/Target.cpp")

add_executable(ExampleCXX "CXX/Main.cpp")
target_link_libraries(ExampleCXX PRIVATE ExampleTarget bcrl)
target_compile_features(ExampleCXX PRIVATE cxx_std_20) # The header uses <span> which is c++20
add_test(NAME TestExampleCXX COMMAND $<TARGET_FILE:ExampleCXX>)

# Include C Support
add_subdirectory("../CWrapper" "CWrapper")

add_executable(ExampleCHeap "C/Heap.c")
target_link_libraries(ExampleCHeap PRIVATE ExampleTarget bcrlCWrapper)

add_executable(ExampleCStack "C/Stack.c")
target_link_libraries(ExampleCStack PRIVATE ExampleTarget bcrlCWrapper)

add_test(NAME TestExampleCHeap COMMAND $<TARGET_FILE:ExampleCHeap>)
add_test(NAME TestExampleCStack COMMAND $<TARGET_FILE:ExampleCStack>)