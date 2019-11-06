project(iSulad_LLT)

# setup testing
find_package(Threads REQUIRED)
find_package(GTest REQUIRED)

add_subdirectory(cutils)
add_subdirectory(image)
add_subdirectory(path)
