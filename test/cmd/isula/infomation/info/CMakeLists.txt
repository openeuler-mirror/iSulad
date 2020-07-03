project(iSulad_UT)

SET(EXE info_ut)

add_executable(${EXE}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/utils_string.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/utils.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/utils_array.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/utils_file.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/utils_convert.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/utils_verify.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/utils_regex.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/util_atomic.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/sha256/sha256.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/path.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/map/map.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/map/rb_tree.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cmd/command_parser.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/console/console.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cmd/isula/client_arguments.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/common/err_msg.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/client/libisula.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/utils_timestamp.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/mainloop.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/error.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/client/connect/isula_connect.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cmd/isula/information/info.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../mocks/grpc_client_mock.cc
    info_ut.cpp)

target_include_directories(${EXE} PUBLIC
    ${GTEST_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/common
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/client
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/map
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/sha256
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/client/connect
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cmd
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/http
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/console
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cmd/isula
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cmd/isula/information
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/client/connect/grpc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/json/schema/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../mocks
    ${CMAKE_BINARY_DIR}/conf
    )
target_link_libraries(${EXE} ${GTEST_BOTH_LIBRARIES} ${GMOCK_LIBRARY} ${GMOCK_MAIN_LIBRARY} ${CMAKE_THREAD_LIBS_INIT} ${ISULA_LIBUTILS_LIBRARY} -lgrpc++ -lprotobuf -lcrypto -lyajl -lz)
