include_guard()

project(BCRLx86)
add_library(BCRLx86 INTERFACE)
target_include_directories(BCRLx86 INTERFACE "${PROJECT_SOURCE_DIR}/Include")

add_subdirectory("${SignatureScanner_SOURCE_DIR}/Modules/XRef" "XRefSignatures")

target_link_libraries(BCRLx86 INTERFACE BCRL XRefSignature)
