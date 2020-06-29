project(iSulad_UT)

SET(EXE path_ut)

add_executable(${EXE}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/utils/cutils/utils.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/utils/cutils/path.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/utils/cutils/map/map.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/utils/cutils/map/rb_tree.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/utils/cutils/utils_string.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/utils/cutils/utils_array.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/utils/cutils/utils_file.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/utils/cutils/utils_convert.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/utils/cutils/utils_regex.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/utils/cutils/utils_verify.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/utils/sha256/sha256.c
    path_ut.cpp)

target_include_directories(${EXE} PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/common
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/utils/cutils/map
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/utils/cutils
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/utils/sha256
    )
set_target_properties(${EXE} PROPERTIES LINK_FLAGS "-Wl,--wrap,getcwd -Wl,--wrap,readlink")
target_link_libraries(${EXE} ${GTEST_BOTH_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} ${ISULA_LIBUTILS_LIBRARY} -lcrypto -lyajl -lz)
