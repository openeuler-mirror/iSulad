project(iSulad_UT)

SET(EXE execution_extend_ut)

add_executable(${EXE}

    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/utils_string.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/utils.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/utils_array.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/utils_file.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/utils_convert.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/utils_verify.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/util_atomic.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/utils_regex.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/sha256/sha256.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/error.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/path.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/map/map.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/map/rb_tree.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/mainloop.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/filters.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/common/err_msg.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/events_sender/event_sender.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/console/console.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/utils.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/utils_verify.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/map/map.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/map/rb_tree.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/executor/container_cb/execution_extend.c
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
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../mocks/container_operator_mock.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../mocks/verify_mock.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../mocks/engine_mock.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../mocks/restartmanager_mock.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../mocks/specs_mock.cc
    execution_extend_ut.cpp)

target_include_directories(${EXE} PUBLIC
    ${GTEST_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/common
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/runtime
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cmd
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cmd/isulad
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/sha256
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/map
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/runtime/engines
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/console
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/config
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/common
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/api
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/image
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/service
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/container
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/container/restart_manager
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/container/health_check
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/container/container_gc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/image/oci
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/executor
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/spec/
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/events
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/events_sender
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/executor/container_cb
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../conf
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../mocks
    )
target_link_libraries(${EXE} ${GTEST_BOTH_LIBRARIES} ${GMOCK_LIBRARY} ${GMOCK_MAIN_LIBRARY} ${CMAKE_THREAD_LIBS_INIT} ${ISULA_LIBUTILS_LIBRARY} -lgrpc++ -lprotobuf -lcrypto -lyajl -lz)
add_test(NAME ${EXE} COMMAND ${EXE})
