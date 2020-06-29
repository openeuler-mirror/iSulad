# get current directory sources files

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} image_top_srcs)
add_subdirectory(external)

set(local_image_srcs
    ${image_top_srcs}
    ${EXTERNAL_SRCS}
    )

set(local_image_incs
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/external
    )

if (ENABLE_OCI_IMAGE)
    add_subdirectory(oci)
    list(APPEND local_image_srcs
	    ${OCI_SRCS}
        )
    list(APPEND local_image_incs
	    ${OCI_INCS}
        )
endif()

if (ENABLE_EMBEDDED_IMAGE)
    add_subdirectory(embedded)
    list(APPEND local_image_srcs
        ${EMBEDDED_SRCS}
        )
    list(APPEND local_image_incs
        ${EMBEDDED_INCS}
        )
endif()

set(IMAGE_SRCS
    ${local_image_srcs}
    PARENT_SCOPE
    )
set(IMAGE_INCS
    ${local_image_incs}
    PARENT_SCOPE
    )

# set sources and headers for libisulad_img
set(LIB_ISULAD_IMG libisulad_img)

add_library(${LIB_ISULAD_IMG} ${LIBTYPE}
    ${local_image_srcs}
    ${CMAKE_SOURCE_DIR}/src/cutils/utils.c
    ${CMAKE_SOURCE_DIR}/src/cutils/utils_regex.c
    ${CMAKE_SOURCE_DIR}/src/cutils/utils_file.c
    ${CMAKE_SOURCE_DIR}/src/cutils/utils_verify.c
    ${CMAKE_SOURCE_DIR}/src/cutils/utils_array.c
    ${CMAKE_SOURCE_DIR}/src/cutils/utils_convert.c
    ${CMAKE_SOURCE_DIR}/src/cutils/utils_string.c
    ${CMAKE_SOURCE_DIR}/src/cutils/utils_base64.c
    ${CMAKE_SOURCE_DIR}/src/cutils/utils_timestamp.c
    ${CMAKE_SOURCE_DIR}/src/cutils/utils_fs.c
    ${CMAKE_SOURCE_DIR}/src/cutils/utils_aes.c
    ${CMAKE_SOURCE_DIR}/src/cutils/util_atomic.c
    ${CMAKE_SOURCE_DIR}/src/cutils/filters.c
    ${CMAKE_SOURCE_DIR}/src/cutils/path.c
    ${CMAKE_SOURCE_DIR}/src/cutils/map/map.c
    ${CMAKE_SOURCE_DIR}/src/cutils/map/rb_tree.c
    ${CMAKE_SOURCE_DIR}/src/sha256/sha256.c
    ${CMAKE_SOURCE_DIR}/src/daemon/libisulad.c
    ${CMAKE_SOURCE_DIR}/src/daemon/isulad_config.c
    ${CMAKE_SOURCE_DIR}/src/daemon/daemon_arguments.c
    ${CMAKE_SOURCE_DIR}/src/daemon/spec/sysinfo.c
    ${CMAKE_SOURCE_DIR}/src/tar/isulad_tar.c
    ${CMAKE_SOURCE_DIR}/src/tar/util_archive.c
    )

target_include_directories(${LIB_ISULAD_IMG} PUBLIC
    ${local_image_incs}
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/sha256
    ${CMAKE_SOURCE_DIR}/src/http
    ${CMAKE_SOURCE_DIR}/src/tar
    ${CMAKE_SOURCE_DIR}/src/daemon
    ${CMAKE_SOURCE_DIR}/src/daemon/spec/
    ${CMAKE_SOURCE_DIR}/src/daemon/container
    ${CMAKE_SOURCE_DIR}/src/daemon/runtime
    ${CMAKE_SOURCE_DIR}/src/daemon/container/restart_manager
    ${CMAKE_SOURCE_DIR}/src/daemon/container/health_check
    ${CMAKE_SOURCE_DIR}/src/cutils
    ${CMAKE_SOURCE_DIR}/src/cutils/map
    ${CHECKED_INCLUDE_DIRS}
    )

# set libisulad_img FLAGS
set_target_properties(${LIB_ISULAD_IMG} PROPERTIES PREFIX "")
target_link_libraries(${LIB_ISULAD_IMG}
    ${CMAKE_THREAD_LIBS_INIT}
    ${ISULA_LIBUTILS_LIBRARY}
    ${DEVMAPPER_LIBRARY}
    ${LIBTAR_LIBRARY}
    -lpthread -lcrypto -larchive -lz libhttpclient)

install(TARGETS ${LIB_ISULAD_IMG}
    LIBRARY DESTINATION ${LIB_INSTALL_DIR_DEFAULT} PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE)