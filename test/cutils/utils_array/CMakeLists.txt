project(iSulad_LLT)

SET(EXE utils_array_llt)

add_executable(${EXE}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/log.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/cutils/utils_string.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/cutils/utils.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/cutils/utils_array.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/cutils/utils_file.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/cutils/utils_convert.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/cutils/utils_verify.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/cutils/utils_regex.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/sha256/sha256.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/path.c
    ${CMAKE_BINARY_DIR}/json/json_common.c
    utils_array_llt.cc)

target_include_directories(${EXE} PUBLIC
    ${GTEST_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/sha256
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/cutils
    ${CMAKE_BINARY_DIR}/json
    )
set_target_properties(${EXE} PROPERTIES LINK_FLAGS "-Wl,--wrap,calloc")
target_link_libraries(${EXE} ${GTEST_BOTH_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} -lyajl -lz)
