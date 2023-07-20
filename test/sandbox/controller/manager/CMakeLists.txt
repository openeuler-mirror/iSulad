project(iSulad_UT)

SET(EXE controller_manager_ut)

add_executable(${EXE}
    ${grpc_sandbox_type_srcs}
    ${CMAKE_BINARY_DIR}/grpc/src/api/services/sandbox/sandbox.pb.cc
    ${CMAKE_BINARY_DIR}/grpc/src/api/services/cri/v1/api_v1.pb.cc
    ${CMAKE_BINARY_DIR}/grpc/src/api/services/cri/gogo.pb.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/utils/cpputils/errors.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/daemon/sandbox/controller/sandboxer/sandboxer_controller.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/daemon/sandbox/controller/shim/shim_controller.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/daemon/sandbox/controller/controller_manager.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../test/mocks/grpc_sandboxer_client_mock.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../test/mocks/isulad_config_mock.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../test/sandbox/controller/controller_common.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/controller_manager_ut.cc)

target_include_directories(${EXE} PUBLIC
    ${GTEST_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../test/sandbox/controller
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../test/mocks
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/daemon/config
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/daemon/entry/cri
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/daemon/sandbox/controller
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/daemon/sandbox/controller/sandboxer
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/daemon/sandbox/controller/sandboxer/client
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/daemon/sandbox/controller/shim
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/common
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/utils/cutils
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/utils/cutils/map
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/utils/sha256
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/utils/cpputils
    ${CMAKE_BINARY_DIR}/grpc/src/api/services/cri
    ${CMAKE_BINARY_DIR}/grpc/src/api/services/cri/v1
    ${CMAKE_BINARY_DIR}/grpc/src/api/services/sandbox
)

target_link_libraries(${EXE} ${GTEST_BOTH_LIBRARIES} ${GMOCK_LIBRARY} ${GMOCK_MAIN_LIBRARY} ${CMAKE_THREAD_LIBS_INIT} ${ISULA_LIBUTILS_LIBRARY} libutils_ut -lgrpc++ -lprotobuf -lcrypto -lyajl -lz)
add_test(NAME ${EXE} COMMAND ${EXE} --gtest_output=xml:${EXE}-Results.xml)
set_tests_properties(${EXE} PROPERTIES TIMEOUT 120)
