project(iSulad_LLT)

SET(EXE path_llt)

add_executable(${EXE}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/cutils/utils.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/cutils/path.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/map/map.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/map/rb_tree.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/cutils/utils_string.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/cutils/utils_array.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/cutils/utils_file.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/cutils/utils_convert.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/cutils/utils_regex.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/cutils/utils_verify.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/sha256/sha256.c
    path_llt.cc)

target_include_directories(${EXE} PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/map
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/cutils
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/sha256
    )
set_target_properties(${EXE} PROPERTIES LINK_FLAGS "-Wl,--wrap,getcwd -Wl,--wrap,readlink")
target_link_libraries(${EXE} ${GTEST_BOTH_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} ${ISULA_LIBUTILS_LIBRARY} -lcrypto -lyajl -lz)
