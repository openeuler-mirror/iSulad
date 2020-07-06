project(iSulad_UT)

SET(EXE registry_images_ut)

add_executable(${EXE}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/utils/cutils/utils.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/utils/cutils/utils_regex.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/utils/cutils/utils_verify.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/utils/cutils/utils_array.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/utils/cutils/utils_string.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/utils/cutils/utils_convert.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/utils/cutils/utils_file.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/utils/cutils/utils_base64.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/utils/cutils/util_atomic.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/utils/sha256/sha256.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/utils/cutils/path.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/utils/cutils/map/map.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/utils/cutils/map/rb_tree.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/utils/cutils/utils_timestamp.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/daemon/modules/image/oci/utils_images.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/daemon/common/err_msg.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/daemon/config/daemon_arguments.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/utils/http/parser.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/utils/http/buffer.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/utils/cutils/utils_aes.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/daemon/modules/image/oci/storage/image_store/image_type.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/daemon/config/isulad_config.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/daemon/modules/image/oci/registry_type.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/daemon/common/sysinfo.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/daemon/modules/image/oci/storage/image_store/image_store.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/daemon/modules/image/oci/registry/registry.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/daemon/modules/image/oci/registry/registry_apiv2.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/daemon/modules/image/oci/registry/http_request.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/daemon/modules/image/oci/registry/certs.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/daemon/modules/image/oci/registry/auths.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/daemon/modules/image/oci/registry/aes.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../mocks/storage_mock.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../mocks/http_mock.cc
    registry_ut.cpp)

target_include_directories(${EXE} PUBLIC
    ${GTEST_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../include
    ${CMAKE_BINARY_DIR}/conf
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/common
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/utils/tar
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/utils/cutils
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/utils/cutils/map
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/utils/sha256
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/utils/http
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/daemon/modules/image/oci
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/daemon/modules/api
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/daemon/config
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/daemon/common
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/daemon
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/daemon/modules/image/oci/storage
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/daemon/modules/image/oci/storage/image_store
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/daemon/modules/image/oci/registry
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../mocks
    )

target_link_libraries(${EXE} ${GTEST_BOTH_LIBRARIES} ${GMOCK_LIBRARY} ${GMOCK_MAIN_LIBRARY} ${CMAKE_THREAD_LIBS_INIT} ${ISULA_LIBUTILS_LIBRARY} -lcrypto -lyajl -lz libhttpclient)
add_test(NAME ${EXE} COMMAND ${EXE})
