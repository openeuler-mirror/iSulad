project(iSulad_LLT)

SET(EXE execution_extend_llt)

add_executable(${EXE}

    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cutils/utils_string.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cutils/utils.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cutils/utils_array.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cutils/utils_file.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cutils/utils_convert.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cutils/utils_verify.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cutils/util_atomic.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cutils/utils_regex.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/sha256/sha256.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/error.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/path.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/map/map.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/map/rb_tree.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/mainloop.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/filters.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/libisulad.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/console/console.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cutils/utils.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cutils/utils_verify.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/map/map.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/map/rb_tree.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/services/execution/execute/execution_extend.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../mocks/runtime_mock.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../mocks/containers_store_mock.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../mocks/collector_mock.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../mocks/containers_gc_mock.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../mocks/container_unix_mock.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../mocks/health_check_mock.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../mocks/image_mock.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../mocks/isulad_config_mock.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../mocks/sysinfo_mock.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../mocks/container_state_mock.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../mocks/verify_mock.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../mocks/engine_mock.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../mocks/driver_mock.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../mocks/restartmanager_mock.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../mocks/specs_mock.cc
    execution_extend_llt.cc)

target_include_directories(${EXE} PUBLIC
    ${GTEST_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/runtime
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cmd
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/sha256
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/map
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/engines
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/console
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/config
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cutils
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/image
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/image/oci
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/services
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/services/execution/manager
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/services/execution/spec
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/services/execution/events
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/services/execution/execute
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/services/graphdriver
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../conf
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../mocks
    )
target_link_libraries(${EXE} ${GTEST_BOTH_LIBRARIES} ${GMOCK_LIBRARY} ${GMOCK_MAIN_LIBRARY} ${CMAKE_THREAD_LIBS_INIT} ${ISULA_LIBUTILS_LIBRARY} -lgrpc++ -lprotobuf -lcrypto -lyajl -lz)
