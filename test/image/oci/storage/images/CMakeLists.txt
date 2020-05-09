project(iSulad_LLT)

SET(EXE storage_images_llt)

add_executable(${EXE}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cutils/utils.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cutils/utils_regex.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cutils/utils_verify.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cutils/utils_array.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cutils/utils_string.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cutils/utils_convert.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cutils/utils_file.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cutils/utils_images.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cutils/util_atomic.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/log.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/sha256/sha256.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/path.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/map/map.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/map/rb_tree.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/json/schema/src/read_file.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/types_def.c
    ${CMAKE_BINARY_DIR}/json/json_common.c
    ${CMAKE_BINARY_DIR}/json/defs.c
    ${CMAKE_BINARY_DIR}/json/storage_image.c
    ${CMAKE_BINARY_DIR}/json/oci_image_spec.c
    ${CMAKE_BINARY_DIR}/json/docker_image_config_v2.c
    ${CMAKE_BINARY_DIR}/json/container_config.c
    ${CMAKE_BINARY_DIR}/json/docker_image_rootfs.c
    ${CMAKE_BINARY_DIR}/json/docker_image_history.c
    ${CMAKE_BINARY_DIR}/json/imagetool_fs_info.c
    ${CMAKE_BINARY_DIR}/json/imagetool_image.c
    ${CMAKE_BINARY_DIR}/json/imagetool_images_list.c
    ${CMAKE_BINARY_DIR}/json/imagetool_fs_info.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/image/oci/storage/image_store/image.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/image/oci/storage/image_store/image_store.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../mocks/storage_mock.cc
    storage_images_llt.cc)

target_include_directories(${EXE} PUBLIC
    ${GTEST_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/tar
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cutils
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/map
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/sha256
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/json/schema/src
    ${CMAKE_BINARY_DIR}/conf
    ${CMAKE_BINARY_DIR}/json
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../test/mocks
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/image/oci/storage
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/image/oci/storage/image_store
    )

target_link_libraries(${EXE} ${GTEST_BOTH_LIBRARIES} ${GMOCK_LIBRARY} ${GMOCK_MAIN_LIBRARY} ${CMAKE_THREAD_LIBS_INIT} -lwebsockets -lcrypto -lyajl -lz)
