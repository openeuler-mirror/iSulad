project(iSulad_UT)

SET(EXE shim_controller_ut)

add_executable(${EXE}
    ${CMAKE_BINARY_DIR}/grpc/src/api/services/cri/v1/api_v1.pb.cc
    ${CMAKE_BINARY_DIR}/grpc/src/api/services/cri/gogo.pb.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/daemon/common/cri/v1/v1_cri_helpers.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/daemon/common/cri/v1/v1_cri_security_context.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/daemon/common/cri/v1/v1_naming.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/daemon/common/cri/checkpoint_handler.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/daemon/common/cri/cri_constants.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/daemon/common/cri/cri_helpers.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/daemon/common/err_msg.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/daemon/config/daemon_arguments.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/daemon/config/isulad_config.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/daemon/sandbox/controller/shim/shim_controller.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/utils/cpputils/errors.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/utils/cpputils/cxxutils.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/utils/sha256/sha256.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../test/mocks/callback_mock.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../test/mocks/image_api_mock.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../test/mocks/service_container_api_mock.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../test/sandbox/controller/controller_common.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../test/sandbox/controller/shim/shim_controller_ut.cc
)

target_include_directories(${EXE} PUBLIC
    ${GTEST_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/daemon/common
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/daemon/common/cri
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/daemon/common/cri/v1
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/daemon/config
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/daemon/executor
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/daemon/modules/api
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/daemon/modules/image
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/daemon/modules/image/external
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/daemon/modules/image/oci
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/daemon/modules/image/oci/storage
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/daemon/modules/image/oci/storage/layer_store/graphdriver
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/daemon/modules/image/oci/storage/layer_store/graphdriver/overlay2
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/daemon/modules/image/oci/storage/layer_store/graphdriver/devmapper
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/daemon/sandbox/controller
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/daemon/sandbox/controller/shim
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/utils/cpputils
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/utils/sha256
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../test/sandbox/controller
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../test/mocks
    ${CMAKE_BINARY_DIR}/grpc/src/api/services/cri
    ${CMAKE_BINARY_DIR}/grpc/src/api/services/cri/v1
)

target_link_libraries(${EXE} ${GTEST_BOTH_LIBRARIES} ${GMOCK_LIBRARY} ${GMOCK_MAIN_LIBRARY} ${CMAKE_THREAD_LIBS_INIT} ${ISULA_LIBUTILS_LIBRARY} libutils_ut -lgrpc++ -lprotobuf -lcrypto -lyajl -lz)
target_link_libraries(${EXE} -Wl,--as-needed ${ISULAD_ABSL_USED_TARGETS})
add_test(NAME ${EXE} COMMAND ${EXE} --gtest_output=xml:${EXE}-Results.xml)
set_tests_properties(${EXE} PROPERTIES TIMEOUT 120)
