project(iSulad_UT)

# storage_driver_ut
SET(DRIVER_EXE storage_driver_ut)

add_executable(${DRIVER_EXE}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/utils.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/utils_regex.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/utils_verify.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/utils_array.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/utils_string.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/utils_convert.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/utils_file.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/utils_fs.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/util_atomic.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/utils_base64.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/utils_timestamp.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/path.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/map/map.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/map/rb_tree.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/tar/util_archive.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/sha256/sha256.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/common/err_msg.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/common/selinux_label.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/config/daemon_arguments.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/config/isulad_config.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/image/oci/storage/layer_store/graphdriver/driver.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/image/oci/storage/layer_store/graphdriver/devmapper/deviceset.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/image/oci/storage/layer_store/graphdriver/devmapper/driver_devmapper.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/image/oci/storage/layer_store/graphdriver/devmapper/metadata_store.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/image/oci/storage/layer_store/graphdriver/devmapper/wrapper_devmapper.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/image/oci/storage/layer_store/graphdriver/overlay2/driver_overlay2.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/image/oci/storage/layer_store/graphdriver/quota/project_quota.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../mocks/driver_quota_mock.cc
    storage_driver_ut.cc)

target_include_directories(${DRIVER_EXE} PUBLIC
    ${GTEST_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/common
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/tar
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/map
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/sha256
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/console
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/buffer
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/config
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/common
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/api
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/image
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/image/oci/storage
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/image/oci/storage/layer_store/graphdriver
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/image/oci/storage/layer_store/graphdriver/devmapper
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/image/oci/storage/layer_store/graphdriver/overlay2
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/image/oci/storage/layer_store/graphdriver/quota
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../mocks
    )

target_link_libraries(${DRIVER_EXE}
    ${GTEST_BOTH_LIBRARIES}
    ${GMOCK_LIBRARY}
    ${GMOCK_MAIN_LIBRARY}
    ${CMAKE_THREAD_LIBS_INIT}
    ${ISULA_LIBUTILS_LIBRARY}
    ${LIBTAR_LIBRARY}
    -lwebsockets -lcrypto -lyajl -larchive ${SELINUX_LIBRARY} -ldevmapper -lz)

add_test(NAME ${DRIVER_EXE} COMMAND ${DRIVER_EXE}  --gtest_output=xml:${DRIVER_EXE}-Results.xml)

# storage_layers_ut
SET(LAYER_EXE storage_layers_ut)

aux_source_directory(${CMAKE_BINARY_DIR}/json json_files)

add_executable(${LAYER_EXE}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/utils.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/utils_regex.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/utils_verify.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/utils_array.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/utils_string.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/utils_convert.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/utils_file.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/utils_fs.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/util_atomic.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/utils_base64.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/utils_timestamp.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/path.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/map/map.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/map/rb_tree.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/buffer/buffer.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/tar/util_archive.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/tar/util_gzip.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/sha256/sha256.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/config/daemon_arguments.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/config/isulad_config.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/common/err_msg.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/common/selinux_label.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/image/oci/storage/layer_store/layer.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/image/oci/storage/layer_store/layer_store.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/image/oci/storage/layer_store/graphdriver/driver.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/image/oci/storage/layer_store/graphdriver/devmapper/deviceset.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/image/oci/storage/layer_store/graphdriver/devmapper/driver_devmapper.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/image/oci/storage/layer_store/graphdriver/devmapper/metadata_store.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/image/oci/storage/layer_store/graphdriver/devmapper/wrapper_devmapper.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/image/oci/storage/layer_store/graphdriver/overlay2/driver_overlay2.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/image/oci/storage/layer_store/graphdriver/quota/project_quota.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../mocks/driver_quota_mock.cc
    storage_layers_ut.cc)

target_include_directories(${LAYER_EXE} PUBLIC
    ${GTEST_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/common
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/tar
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/map
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/http
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/sha256
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/console
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/buffer
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/config
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/common
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/api
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/image
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/image/oci/storage
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/image/oci/storage/layer_store
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/image/oci/storage/layer_store/graphdriver
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/image/oci/storage/layer_store/graphdriver/devmapper
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/image/oci/storage/layer_store/graphdriver/overlay2
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/image/oci/storage/layer_store/graphdriver/quota
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../mocks
    )

target_link_libraries(${LAYER_EXE}
    ${GTEST_BOTH_LIBRARIES}
    ${GMOCK_LIBRARY}
    ${GMOCK_MAIN_LIBRARY}
    ${CMAKE_THREAD_LIBS_INIT}
    ${ISULA_LIBUTILS_LIBRARY}
    ${LIBTAR_LIBRARY}
    -lwebsockets -lcrypto -lyajl -larchive ${SELINUX_LIBRARY} -ldevmapper -lz)

add_test(NAME ${LAYER_EXE} COMMAND ${LAYER_EXE} --gtest_output=xml:${LAYER_EXE}-Results.xml)
