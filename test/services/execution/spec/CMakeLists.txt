project(iSulad_UT)

SET(EXE selinux_label_ut)
SET(MOCK_EXE selinux_label_mock_ut)

add_executable(${EXE}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/utils/cutils/utils.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/utils/cutils/utils_regex.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/utils/cutils/utils_verify.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/utils/cutils/utils_array.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/utils/cutils/utils_string.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/utils/cutils/utils_convert.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/utils/cutils/utils_file.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/utils/sha256/sha256.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/utils/cutils/path.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/utils/cutils/map/map.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/utils/cutils/map/rb_tree.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/daemon/libisulad.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../mocks/namespace_mock.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/daemon/spec//selinux_label.c
    selinux_label_ut.cpp)

add_executable(${MOCK_EXE}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/utils/cutils/utils.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/utils/cutils/utils_regex.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/utils/cutils/utils_verify.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/utils/cutils/utils_array.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/utils/cutils/utils_string.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/utils/cutils/utils_convert.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/utils/cutils/utils_file.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/utils/sha256/sha256.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/utils/cutils/path.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/utils/cutils/map/map.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/utils/cutils/map/rb_tree.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/daemon/libisulad.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../mocks/namespace_mock.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../mocks/syscall_mock.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../mocks/selinux_mock.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/daemon/spec//selinux_label.c
    selinux_label_mock_ut.cpp)

target_include_directories(${EXE} PUBLIC
    ${GTEST_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/daemon
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/utils/cutils
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/utils/sha256
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/utils/cutils/map
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/daemon/services/execution/manager
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../mocks
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/daemon/spec/
    ${CMAKE_BINARY_DIR}/conf
    )

target_include_directories(${MOCK_EXE} PUBLIC
    ${GTEST_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/daemon
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/utils/cutils
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/utils/sha256
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/utils/cutils/map
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/daemon/services/execution/manager
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../mocks
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/daemon/spec/
    ${CMAKE_BINARY_DIR}/conf
    )

target_link_libraries(${EXE} ${GTEST_BOTH_LIBRARIES} ${GMOCK_LIBRARY} ${GMOCK_MAIN_LIBRARY} ${CMAKE_THREAD_LIBS_INIT} ${SELINUX_LIBRARY} ${ISULA_LIBUTILS_LIBRARY} -lcrypto -lyajl -lz)
target_link_libraries(${MOCK_EXE} ${GTEST_BOTH_LIBRARIES} ${GMOCK_LIBRARY} ${GMOCK_MAIN_LIBRARY} ${CMAKE_THREAD_LIBS_INIT} ${SELINUX_LIBRARY} ${ISULA_LIBUTILS_LIBRARY} -lcrypto -lyajl -lz)
