project(iSulad_UT)

SET(EXE cni_operate_ut)

add_executable(${EXE}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/utils/cutils/utils.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/utils/cutils/util_atomic.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/utils/cutils/utils_mount_spec.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/utils/cutils/utils_network.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/utils/cutils/utils_fs.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/utils/cutils/utils_file.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/utils/cutils/utils_convert.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/utils/cutils/utils_verify.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/utils/cutils/utils_string.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/utils/cutils/utils_array.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/utils/cutils/utils_regex.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/utils/cutils/utils_version.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/utils/cutils/namespace.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/utils/sha256/sha256.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/utils/cutils/path.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/utils/cutils/map/map.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/utils/cutils/map/rb_tree.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/cmd/isulad-shim/common.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/daemon/common/err_msg.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/daemon/modules/network/cni_operator/libcni/libcni_result_type.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/daemon/modules/network/cni_operator/libcni/invoke/libcni_errno.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/daemon/modules/network/cni_operator/libcni/invoke/libcni_exec.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/daemon/modules/network/cni_operator/libcni/invoke/libcni_result_parse.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/daemon/modules/network/cni_operator/libcni/libcni_conf.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/daemon/modules/network/cni_operator/libcni/libcni_api.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/daemon/modules/network/cni_operator/libcni/libcni_cached.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/daemon/modules/network/cni_operator/cni_operate.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../test/image/oci/oci_ut_common.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../test/network/network_mock.cc
cni_operate_ut.cc)

target_include_directories(${EXE} PUBLIC
    ${GTEST_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/cmd/isulad-shim
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/common
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/utils/cutils
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/utils/cutils/map
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/daemon/common
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/daemon/modules/network/cni_operator/libcni/invoke
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/daemon/modules/network/cni_operator/libcni
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/daemon/modules/network/cni_operator
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/daemon/modules/network
    ${ENGINES_INCS}
    ${RUNTIME_INCS}
    ${IMAGE_INCS}
    ${CMAKE_BINARY_DIR}/conf
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../test/mocks
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../test/image/oci
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../test/network
)

set_target_properties(${EXE} PROPERTIES LINK_FLAGS "-Wl,--wrap,cni_cache_read -Wl,--wrap,cni_check_network_list -Wl,--wrap,util_atomic_write_file -Wl,--wrap,cni_del_network_list -Wl,--wrap,calloc")
target_link_libraries(${EXE} ${GTEST_BOTH_LIBRARIES} ${GMOCK_LIBRARY} ${GMOCK_MAIN_LIBRARY} ${CMAKE_THREAD_LIBS_INIT} ${ISULA_LIBUTILS_LIBRARY} -lgrpc++ -lprotobuf -lcrypto -lyajl -lz)
add_test(NAME ${EXE} COMMAND ${EXE} --gtest_output=xml:${EXE}-Results.xml)
set_tests_properties(${EXE} PROPERTIES TIMEOUT 120)
