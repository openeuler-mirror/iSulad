project(iSulad_LLT)

SET(EXE oci_rootfs_prepare_llt)

add_executable(${EXE}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/image/oci/oci_rootfs_prepare.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/cutils/utils.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/cutils/utils_verify.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/cutils/utils_array.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/cutils/utils_string.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/cutils/utils_convert.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/cutils/utils_file.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/log.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/sha256/sha256.c
    ${CMAKE_BINARY_DIR}/json/json_common.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/path.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/services/execution/spec/specs_mount.c
    ${CMAKE_BINARY_DIR}/json/host_config.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/services/execution/spec/specs_extend.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/liblcrd.c
    ${CMAKE_BINARY_DIR}/json/oci_runtime_defs_linux.c
    ${CMAKE_BINARY_DIR}/json/defs.c
    ${CMAKE_BINARY_DIR}/json/container_config_v2.c
    ${CMAKE_BINARY_DIR}/json/container_config.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/config/lcrd_config.c
    ${CMAKE_BINARY_DIR}/json/oci_runtime_spec.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/services/execution/spec/sysinfo.c
    ${CMAKE_BINARY_DIR}/json/oci_runtime_config_linux.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/cmd/commander.c
    ${CMAKE_BINARY_DIR}/json/isulad_daemon_configs.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/json/schema/src/read_file.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/cmd/lcrd/arguments.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/image/oci/isula_imtool_interface.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/services/graphdriver/driver.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/services/graphdriver/overlay2/driver_overlay2.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../test/image/oci/oci_llt_common.cc
    ${CMAKE_BINARY_DIR}/json/imagetool_prepare_response.c
    ${CMAKE_BINARY_DIR}/json/oci_image_spec.c
    oci_rootfs_prepare_llt.cc)

target_include_directories(${EXE} PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../test/image/oci
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/image/oci
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/image
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/cutils
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/json
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/services/execution/spec
    ${CMAKE_BINARY_DIR}/json
    ${CMAKE_BINARY_DIR}/conf
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/sha256
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/config
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/cmd
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/services/graphdriver
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/json/schema/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/console
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/services/graphdriver/overlay2
    )

set_target_properties(${EXE} PROPERTIES LINK_FLAGS "-Wl,--wrap,conf_get_graph_rootpath -Wl,--wrap,conf_get_graph_run_path -Wl,--wrap,conf_get_lcrd_storage_driver -Wl,--wrap,conf_get_storage_opts -Wl,--wrap,conf_get_registry_list -Wl,--wrap,conf_get_insecure_registry_list -Wl,--wrap,conf_get_im_opt_timeout -Wl,--wrap,execvp -Wl,--wrap,util_exec_cmd")
target_link_libraries(${EXE} ${GTEST_BOTH_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} -lyajl -lsecurec -lz)
