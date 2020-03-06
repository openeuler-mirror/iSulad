project(iSulad_LLT)

SET(EXE lcr_rt_ops_llt)

add_executable(${EXE}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/cutils/utils.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/cutils/utils_regex.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/cutils/utils_verify.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/cutils/utils_array.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/cutils/utils_string.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/cutils/utils_convert.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/cutils/utils_file.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/cutils/util_atomic.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/log.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/sha256/sha256.c
    ${CMAKE_BINARY_DIR}/json/json_common.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/path.c
    ${CMAKE_BINARY_DIR}/json/host_config.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/libisulad.c
    ${CMAKE_BINARY_DIR}/json/defs.c
    ${CMAKE_BINARY_DIR}/json/container_config_v2.c
    ${CMAKE_BINARY_DIR}/json/container_config.c
    ${CMAKE_BINARY_DIR}/json/oci_runtime_spec.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/services/execution/spec/sysinfo.c
    ${CMAKE_BINARY_DIR}/json/oci_runtime_config_linux.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/cmd/commander.c
    ${CMAKE_BINARY_DIR}/json/isulad_daemon_configs.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/json/schema/src/read_file.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/cmd/isulad/arguments.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../test/image/oci/oci_llt_common.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../test/mocks/containers_store_mock.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../test/mocks/namespace_mock.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../test/mocks/container_unix_mock.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../test/mocks/engine_mock.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../test/mocks/isulad_config_mock.cc
    ${CMAKE_BINARY_DIR}/json/imagetool_image.c
    ${CMAKE_BINARY_DIR}/json/oci_image_spec.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/runtime/lcr/lcr_rt_ops.c
    lcr_rt_ops_llt.cc)

target_include_directories(${EXE} PUBLIC
    ${GTEST_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/cutils
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/map
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/services/execution/manager
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/services/execution/events
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/runtime
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/runtime/lcr
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/services/execution/spec
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/json
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/engines
    ${CMAKE_BINARY_DIR}/json
    ${CMAKE_BINARY_DIR}/conf
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/sha256
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/config
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/cmd
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/services/graphdriver
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/json/schema/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/console
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../test/mocks
    )

#set_target_properties(${EXE} PROPERTIES LINK_FLAGS)
target_link_libraries(${EXE} ${GTEST_BOTH_LIBRARIES} ${GMOCK_LIBRARY} ${GMOCK_MAIN_LIBRARY} ${CMAKE_THREAD_LIBS_INIT} -lgrpc++ -lprotobuf -lcrypto -lyajl -lz)
