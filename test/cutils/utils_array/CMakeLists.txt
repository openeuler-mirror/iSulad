project(iSulad_UT)

SET(EXE utils_array_ut)

add_executable(${EXE}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/cutils/utils_string.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/cutils/utils.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/cutils/utils_array.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/cutils/utils_file.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/cutils/utils_convert.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/cutils/utils_verify.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/cutils/utils_regex.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/sha256/sha256.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/cutils/map/map.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/cutils/map/rb_tree.c    
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/cutils/path.c
    utils_array_ut.cpp)

target_include_directories(${EXE} PUBLIC
    ${GTEST_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/cutils/map
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/sha256
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/cutils
    )
set_target_properties(${EXE} PROPERTIES LINK_FLAGS "-Wl,--wrap,calloc")
target_link_libraries(${EXE} ${GTEST_BOTH_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} ${ISULA_LIBUTILS_LIBRARY} -lcrypto -lyajl -lz)
