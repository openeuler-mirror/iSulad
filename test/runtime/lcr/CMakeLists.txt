project(iSulad_UT)

SET(EXE lcr_rt_ops_ut)

add_executable(${EXE}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/utils/cutils/utils.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/utils/cutils/utils_regex.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/utils/cutils/utils_verify.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/utils/cutils/utils_array.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/utils/cutils/utils_string.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/utils/cutils/utils_convert.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/utils/cutils/utils_file.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/utils/cutils/util_atomic.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/utils/sha256/sha256.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/utils/cutils/path.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/utils/cutils/map/map.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/utils/cutils/map/rb_tree.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/daemon/libisulad.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/daemon/spec//sysinfo.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/cmd/command_parser.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/daemon/daemon_arguments.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../test/image/oci/oci_ut_common.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../test/mocks/containers_store_mock.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../test/mocks/namespace_mock.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../test/mocks/container_unix_mock.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../test/mocks/engine_mock.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../test/mocks/isulad_config_mock.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/daemon/runtime/engines/lcr/lcr_rt_ops.c
    lcr_rt_ops_ut.cpp)

target_include_directories(${EXE} PUBLIC
    ${GTEST_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/utils/cutils
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/utils/cutils/map
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/daemon
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/daemon/container
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/daemon/container/restart_manager
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/daemon/container/health_check
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/daemon/events
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/daemon/runtime
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/daemon/runtime/engines
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/daemon/runtime/engines/lcr
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/daemon/spec/
    ${CMAKE_BINARY_DIR}/conf
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/utils/sha256
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/config
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/cmd
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/cmd/isulad
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/daemon/services/graphdriver
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/utils/console
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../test/mocks
    )

target_link_libraries(${EXE} ${GTEST_BOTH_LIBRARIES} ${GMOCK_LIBRARY} ${GMOCK_MAIN_LIBRARY} ${CMAKE_THREAD_LIBS_INIT} ${ISULA_LIBUTILS_LIBRARY} -lgrpc++ -lprotobuf -lcrypto -lyajl -lz)
