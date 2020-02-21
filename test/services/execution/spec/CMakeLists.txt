project(iSulad_LLT)

SET(EXE selinux_label_llt)
SET(MOCK_EXE selinux_label_mock_llt)

add_executable(${EXE}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/cutils/utils.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/cutils/utils_regex.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/cutils/utils_verify.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/cutils/utils_array.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/cutils/utils_string.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/cutils/utils_convert.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/cutils/utils_file.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/log.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/sha256/sha256.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/path.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/map/map.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/map/rb_tree.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/libisulad.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/json/schema/src/read_file.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../mocks/namespace_mock.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/services/execution/spec/selinux_label.c
    ${CMAKE_BINARY_DIR}/json/json_common.c
    selinux_label_llt.cc)

add_executable(${MOCK_EXE}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/cutils/utils.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/cutils/utils_regex.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/cutils/utils_verify.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/cutils/utils_array.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/cutils/utils_string.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/cutils/utils_convert.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/cutils/utils_file.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/log.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/sha256/sha256.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/path.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/map/map.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/map/rb_tree.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/libisulad.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/json/schema/src/read_file.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../mocks/namespace_mock.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../mocks/syscall_mock.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../mocks/selinux_mock.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/services/execution/spec/selinux_label.c
    ${CMAKE_BINARY_DIR}/json/json_common.c
    selinux_label_mock_llt.cc)

target_include_directories(${EXE} PUBLIC
    ${GTEST_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/cutils
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/sha256
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/map
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/json/schema/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/services/execution/manager
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../mocks
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/services/execution/spec
    ${CMAKE_BINARY_DIR}/conf
    ${CMAKE_BINARY_DIR}/json
    )

target_include_directories(${MOCK_EXE} PUBLIC
    ${GTEST_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/cutils
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/sha256
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/map
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/json/schema/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/services/execution/manager
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../mocks
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/services/execution/spec
    ${CMAKE_BINARY_DIR}/conf
    ${CMAKE_BINARY_DIR}/json
    )

target_link_libraries(${EXE} ${GTEST_BOTH_LIBRARIES} ${GMOCK_LIBRARY} ${GMOCK_MAIN_LIBRARY} ${CMAKE_THREAD_LIBS_INIT} ${SELINUX_LIBRARY} -lyajl -lz)
target_link_libraries(${MOCK_EXE} ${GTEST_BOTH_LIBRARIES} ${GMOCK_LIBRARY} ${GMOCK_MAIN_LIBRARY} ${CMAKE_THREAD_LIBS_INIT} ${SELINUX_LIBRARY} -lyajl -lz)
