project(iSulad_UT)

SET(EXE pause_ut)

add_executable(${EXE}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cutils/utils_string.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cutils/utils.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cutils/utils_array.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cutils/utils_file.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cutils/utils_convert.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cutils/utils_verify.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cutils/utils_regex.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/sha256/sha256.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cutils/path.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cutils/map/map.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cutils/map/rb_tree.c    
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cmd/command_parser.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/console/console.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cmd/isula/client_arguments.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/libisulad.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/client/libisula.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cutils/utils_timestamp.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cutils/mainloop.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cutils/error.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/client/connect/isula_connect.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cmd/isula/extend/pause.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../mocks/grpc_client_mock.cc
    pause_ut.cpp)

target_include_directories(${EXE} PUBLIC
    ${GTEST_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/client
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/sha256
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cutils
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/client/connect
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cmd
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cutils/map
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/http
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/console
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cmd/isula
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cmd/isula/extend
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/client/connect/grpc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../mocks
    ${CMAKE_BINARY_DIR}/conf
    )
target_link_libraries(${EXE} ${GTEST_BOTH_LIBRARIES} ${GMOCK_LIBRARY} ${GMOCK_MAIN_LIBRARY} ${CMAKE_THREAD_LIBS_INIT} ${ISULA_LIBUTILS_LIBRARY} -lgrpc++ -lprotobuf -lcrypto -lyajl -lz)
