project(iSulad_UT)

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
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/image/oci/storage/layer_store/graphdriver/driver.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/image/oci/storage/layer_store/graphdriver/devmapper/deviceset.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/image/oci/storage/layer_store/graphdriver/devmapper/driver_devmapper.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/image/oci/storage/layer_store/graphdriver/devmapper/metadata_store.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/image/oci/storage/layer_store/graphdriver/devmapper/wrapper_devmapper.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/image/oci/storage/layer_store/graphdriver/overlay2/driver_overlay2.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/image/oci/storage/layer_store/graphdriver/quota/project_quota.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../mocks/driver_quota_mock.cc
    storage_driver_ut.cpp)

target_include_directories(${DRIVER_EXE} PUBLIC
    ${GTEST_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/common
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/tar
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/map
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/sha256
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/console
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/config
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/common
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/api
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/image
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/image/oci/storage
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/image/oci/storage/layer_store/graphdriver
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/image/oci/storage/layer_store/graphdriver/devmapper/
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
    -lwebsockets -lcrypto -lyajl -larchive -ldevmapper -lz)

add_test(NAME ${DRIVER_EXE} COMMAND ${DRIVER_EXE})

#[[
SET(EXE storage_layers_ut)

aux_source_directory(${CMAKE_BINARY_DIR}/json json_files)

add_executable(${EXE}
    ${json_files}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/utils.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/utils_regex.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/utils_verify.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/utils_array.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/utils_string.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/utils_convert.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/utils_file.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/utils_fs.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/util_atomic.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/log.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/tar/isulad_tar.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/tar/util_archive.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/sha256/sha256.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/path.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/mainloop.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/map/map.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/map/rb_tree.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/json/schema/src/isula_utils_read_file.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/utils_timestamp.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/console/console.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/image/oci/storage/storage.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/image/oci/storage/image_store/image.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/image/oci/storage/image_store/image_store.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/image/oci/storage/layer_store/layer_store.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/image/oci/storage/layer_store/layer.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/image/oci/storage/layer_store/graphdriver/driver.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/image/oci/storage/layer_store/graphdriver/quota/project_quota.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/image/oci/storage/layer_store/graphdriver/overlay2/driver_overlay2.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/image/oci/storage/layer_store/graphdriver/devmapper/deviceset.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/image/oci/storage/layer_store/graphdriver/devmapper/metadata_store.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/image/oci/storage/layer_store/graphdriver/devmapper/device_setup.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/image/oci/storage/layer_store/graphdriver/devmapper/wrapper_devmapper.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/image/oci/storage/layer_store/graphdriver/devmapper/driver_devmapper.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../mocks/storage_mock.cc
    storage_layers_ut.cpp)

target_include_directories(${EXE} PUBLIC
    ${GTEST_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/tar
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/cutils/map
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/sha256
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/utils/console
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/json/schema/src
    ${CMAKE_BINARY_DIR}/conf
    ${CMAKE_BINARY_DIR}/json
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../test/mocks
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/image/oci/storage
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/image/oci/storage/image_store
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/image/oci/storage/layer_store
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/image/oci/storage/layer_store/graphdriver
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/image/oci/storage/layer_store/graphdriver/devmapper
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/image/oci/storage/layer_store/graphdriver/quota
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/modules/image/oci/storage/layer_store/graphdriver/overlay2
    )

target_link_libraries(${EXE}
    ${GTEST_BOTH_LIBRARIES}
    ${GMOCK_LIBRARY}
    ${GMOCK_MAIN_LIBRARY}
    ${CMAKE_THREAD_LIBS_INIT}
    -lwebsockets -lcrypto -lyajl -larchive -ldevmapper -lz)
]]
