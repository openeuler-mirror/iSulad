project(iSulad_UT)

SET(EXE sandbox_ut)

aux_source_directory(${CMAKE_BINARY_DIR}/grpc/src/api/services/sandbox/sandbox/types sandbox_type_srcs)

add_executable(${EXE}
    ${sandbox_type_srcs}
    ${CMAKE_BINARY_DIR}/grpc/src/api/services/sandbox/sandbox.pb.cc
    ${CMAKE_BINARY_DIR}/grpc/src/api/services/cri/v1/api_v1.pb.cc
    ${CMAKE_BINARY_DIR}/grpc/src/api/services/cri/gogo.pb.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/utils/cpputils/errors.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/utils/cpputils/read_write_lock.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/utils/cpputils/transform.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/utils/cpputils/cxxutils.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/daemon/sandbox/sandbox.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/daemon/sandbox/controller/controller_manager.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/daemon/sandbox/controller/sandboxer/sandboxer_controller.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/daemon/common/id_name_manager.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/daemon/config/isulad_config.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../test/sandbox/controller/controller_common.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/daemon/config/daemon_arguments.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../test/mocks/grpc_sandboxer_client_mock.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../test/mocks/controller_stub_mock.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../test/mocks/shim_controller_mock.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../test/mocks/mailbox_mock.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/daemon/common/err_msg.c
    ${CMAKE_CURRENT_SOURCE_DIR}/sandbox_ut.cc)

target_include_directories(${EXE} PUBLIC
    ${GTEST_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../test/mocks
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/daemon/common
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/daemon/config
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/daemon/entry/cri
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/daemon/executor
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/daemon/mailbox
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/daemon/sandbox/controller
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/daemon/sandbox/controller/shim
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/daemon/sandbox/controller/sandboxer
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/daemon/sandbox/controller/sandboxer/client
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/daemon/sandbox
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/daemon/common
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/utils/cpputils
    ${CMAKE_BINARY_DIR}/grpc/src/api/services/cri
    ${CMAKE_BINARY_DIR}/grpc/src/api/services/cri/v1
    ${CMAKE_BINARY_DIR}/grpc/src/api/services/sandbox
    ${CMAKE_BINARY_DIR}/grpc/src/api/services/sandbox/google/protobuf
    ${CMAKE_BINARY_DIR}/grpc/src/api/services/sandbox/sandbox/types
)

target_link_libraries(${EXE} ${GTEST_BOTH_LIBRARIES} ${GMOCK_LIBRARY} ${GMOCK_MAIN_LIBRARY} ${CMAKE_THREAD_LIBS_INIT} ${ISULA_LIBUTILS_LIBRARY} libutils_ut -lgrpc -lgrpc++ -lprotobuf -lcrypto -lyajl -lz)
target_link_libraries(${EXE} -Wl,--as-needed ${ISULAD_ABSL_USED_TARGETS})
add_test(NAME ${EXE} COMMAND ${EXE} --gtest_output=xml:${EXE}-Results.xml)
set_tests_properties(${EXE} PROPERTIES TIMEOUT 120)
