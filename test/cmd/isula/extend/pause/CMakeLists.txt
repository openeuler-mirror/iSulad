project(iSulad_LLT)

SET(EXE pause_llt)

add_executable(${EXE}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/log.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cutils/utils_string.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cutils/utils.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cutils/utils_array.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cutils/utils_file.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cutils/utils_convert.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cutils/utils_verify.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cutils/utils_regex.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/sha256/sha256.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/path.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cmd/commander.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/console/console.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cmd/isula/arguments.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/libisulad.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/libisula.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/types_def.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/mainloop.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/container_def.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/error.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/connect/client/isula_connect.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/json/schema/src/read_file.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cmd/isula/extend/pause.c
    # ${CMAKE_CURRENT_SOURCE_DIR}/../../../../mocks/LcrcConnectMock.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../mocks/grpc_client_mock.cc
    ${CMAKE_BINARY_DIR}/json/json_common.c
    ${CMAKE_BINARY_DIR}/json/host_config.c
    ${CMAKE_BINARY_DIR}/json/container_path_stat.c
    ${CMAKE_BINARY_DIR}/json/timestamp.c
    pause_llt.cc)

target_include_directories(${EXE} PUBLIC
    ${GTEST_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/json
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/sha256
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cutils
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/connect/client
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cmd
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/http
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/console
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cmd/isula
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cmd/isula/extend
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/connect/client/grpc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/json/schema/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../mocks
    ${CMAKE_BINARY_DIR}/json
    ${CMAKE_BINARY_DIR}/conf
    )
target_link_libraries(${EXE} ${GTEST_BOTH_LIBRARIES} ${GMOCK_LIBRARY} ${GMOCK_MAIN_LIBRARY} ${CMAKE_THREAD_LIBS_INIT} -lgrpc++ -lprotobuf -lcrypto -lyajl -lz)
