project(iSulad_UT)

SET(EXE sandboxer_client_async_wait_call_ut)

add_executable(${EXE}
    ${grpc_sandbox_type_srcs}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/sandbox/controller/sandboxer/client/grpc_async_wait_call.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/sandbox/controller/sandboxer/client/grpc_client_utils.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cpputils/errors.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../test/mocks/controller_stub_mock.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/async_wait_call_ut.cc)

target_include_directories(${EXE} PUBLIC
    ${GTEST_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../test/sandbox/controller
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../test/sandbox/controller/sandboxer/async_wait_call
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../test/mocks
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/entry/cri
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/sandbox/controller
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/sandbox/controller/sandboxer
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/sandbox/controller/sandboxer/client
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/common
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/map
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/sha256
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cpputils
    ${CMAKE_BINARY_DIR}/grpc/src/api/services/cri
    ${CMAKE_BINARY_DIR}/grpc/src/api/services/cri/v1
    ${CMAKE_BINARY_DIR}/grpc/src/api/services/sandbox
    ${CMAKE_BINARY_DIR}/grpc/src/api/services/sandbox/google/protobuf
    ${CMAKE_BINARY_DIR}/grpc/src/api/services/sandbox/sandbox/types
)

target_link_libraries(${EXE} ${GTEST_BOTH_LIBRARIES} ${GMOCK_LIBRARY} ${GMOCK_MAIN_LIBRARY} ${CMAKE_THREAD_LIBS_INIT} ${ISULA_LIBUTILS_LIBRARY} libutils_ut -lgrpc++ -lprotobuf -lcrypto -lyajl -lz)
if(ABSL_SYNC_LIB)
    target_link_libraries(${EXE} -Wl,--no-as-needed ${ABSL_SYNC_LIB})
endif()
add_test(NAME ${EXE} COMMAND ${EXE} --gtest_output=xml:${EXE}-Results.xml)
set_tests_properties(${EXE} PROPERTIES TIMEOUT 120)
