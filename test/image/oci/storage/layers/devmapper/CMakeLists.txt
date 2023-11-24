project(iSulad_UT)

# driver_devmapper_ut
SET(DRIVER_DEVMAPPER_EXE driver_devmapper_ut)

add_executable(${DRIVER_DEVMAPPER_EXE}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../../src/utils/cutils/utils.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../../src/utils/cutils/utils_regex.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../../src/utils/cutils/utils_verify.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../../src/utils/cutils/utils_array.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../../src/utils/cutils/utils_string.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../../src/utils/cutils/utils_convert.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../../src/utils/cutils/utils_file.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../../src/utils/cutils/utils_fs.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../../src/utils/cutils/util_atomic.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../../src/utils/cutils/utils_base64.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../../src/utils/cutils/utils_timestamp.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../../src/utils/cutils/path.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../../src/utils/cutils/map/map.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../../src/utils/cutils/map/rb_tree.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../../src/utils/buffer/buffer.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../../src/utils/tar/util_archive.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../../src/utils/tar/util_gzip.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../../src/utils/sha256/sha256.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../../src/daemon/config/daemon_arguments.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../../src/daemon/config/isulad_config.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../../src/daemon/common/err_msg.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../../src/daemon/common/selinux_label.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../../src/daemon/modules/image/oci/storage/layer_store/graphdriver/devmapper/deviceset.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../../src/daemon/modules/image/oci/storage/layer_store/graphdriver/devmapper/driver_devmapper.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../../src/daemon/modules/image/oci/storage/layer_store/graphdriver/devmapper/metadata_store.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../../src/daemon/modules/image/oci/storage/layer_store/graphdriver/devmapper/wrapper_devmapper.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../mocks/libdevmapper_mock.cc
    driver_devmapper_ut.cc)

target_include_directories(${DRIVER_DEVMAPPER_EXE} PUBLIC
    ${GTEST_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../../src/common
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../../src/utils/tar
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../../src/utils/cutils
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../../src/utils/cutils/map
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../../src/utils/sha256
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../../src/utils/console
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../../src/utils/buffer
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../../src/daemon/config
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../../src/daemon/common
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../../src/daemon/modules/api
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../../src/daemon/modules/image
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../../src/daemon/modules/image/oci/storage
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../../src/daemon/modules/image/oci/storage/layer_store/graphdriver
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../../src/daemon/modules/image/oci/storage/layer_store/graphdriver/devmapper
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../../src/daemon/modules/image/oci/storage/layer_store/graphdriver/overlay2
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../../src/daemon/modules/image/oci/storage/remote_layer_support
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../../src/daemon/modules/image/oci/storage/layer_store/graphdriver/quota
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../mocks
    )

set_target_properties(${DRIVER_DEVMAPPER_EXE} PROPERTIES LINK_FLAGS "-Wl,--wrap,util_exec_cmd -Wl,--wrap,util_mount -Wl,--wrap,umount2")

target_link_libraries(${DRIVER_DEVMAPPER_EXE}
    ${GTEST_BOTH_LIBRARIES}
    ${GMOCK_LIBRARY}
    ${GMOCK_MAIN_LIBRARY}
    ${CMAKE_THREAD_LIBS_INIT}
    ${ISULA_LIBUTILS_LIBRARY}
    ${LIBTAR_LIBRARY}
    -lcrypto -lyajl -larchive ${SELINUX_LIBRARY} -lz -lcap)

add_test(NAME ${DRIVER_DEVMAPPER_EXE} COMMAND ${DRIVER_DEVMAPPER_EXE}  --gtest_output=xml:${DRIVER_DEVMAPPER_EXE}-Results.xml)
set_tests_properties(${DRIVER_DEVMAPPER_EXE} PROPERTIES TIMEOUT 120)
