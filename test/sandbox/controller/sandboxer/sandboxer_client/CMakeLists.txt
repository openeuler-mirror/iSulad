project(iSulad_UT)

SET(EXE controller_sandboxer_client_ut)

add_executable(${EXE}
    ${grpc_sandbox_type_srcs}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/sandbox/sandboxer/controller/client/grpc_sandboxer_client.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cpputils/errors.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cpputils/transform.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../test/mocks/sandbox_manager_mock.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../test/mocks/rust_sandbox_api_mock.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../test/sandbox/controller/controller_common.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/sandboxer_client_ut.cc)

target_include_directories(${EXE} PUBLIC
    ${GTEST_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../test/sandbox/controller
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../test/mocks
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/config
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/entry/cri
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/sandbox
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/sandbox/sandboxer
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/sandbox/sandboxer/controller
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/sandbox/sandboxer/controller/client
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/common
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/map
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/sha256
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cpputils
    ${CMAKE_BINARY_DIR}/grpc/src/api/services/cri
    ${CMAKE_BINARY_DIR}/grpc/src/api/services/cri/v1
)

target_link_libraries(${EXE} ${GTEST_BOTH_LIBRARIES} ${GMOCK_LIBRARY} ${GMOCK_MAIN_LIBRARY} ${CMAKE_THREAD_LIBS_INIT} ${ISULA_LIBUTILS_LIBRARY} libutils_ut -lgrpc -lgrpc++ -lprotobuf -lcrypto -lyajl -lz)
target_link_libraries(${EXE} -Wl,--as-needed ${ISULAD_ABSL_USED_TARGETS})
add_test(NAME ${EXE} COMMAND ${EXE} --gtest_output=xml:${EXE}-Results.xml)
set_tests_properties(${EXE} PROPERTIES TIMEOUT 120)
