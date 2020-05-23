project(iSulad_UT)

SET(EXE storage_rootfs_ut)

add_executable(${EXE}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cutils/utils.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cutils/utils_regex.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cutils/utils_verify.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cutils/utils_array.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cutils/utils_string.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cutils/utils_convert.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cutils/utils_file.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cutils/utils_base64.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cutils/util_atomic.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/sha256/sha256.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cutils/path.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cutils/map/map.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cutils/map/rb_tree.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cutils/utils_timestamp.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/image/oci/utils_images.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/image/oci/storage/rootfs_store/rootfs.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/image/oci/storage/rootfs_store/rootfs_store.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../mocks/storage_mock.cc
    storage_rootfs_ut.cpp)

target_include_directories(${EXE} PUBLIC
    ${GTEST_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/tar
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cutils
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/cutils/map
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/sha256
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/json/schema/src
    ${CMAKE_BINARY_DIR}/conf
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../test/mocks
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/image/oci
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/image/oci/storage
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/daemon/image/oci/storage/rootfs_store
    )

target_link_libraries(${EXE} ${GTEST_BOTH_LIBRARIES} ${GMOCK_LIBRARY} ${GMOCK_MAIN_LIBRARY} ${CMAKE_THREAD_LIBS_INIT} ${ISULA_LIBUTILS_LIBRARY} -lcrypto -lyajl -lz)
