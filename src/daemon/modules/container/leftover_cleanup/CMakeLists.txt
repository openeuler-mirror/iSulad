# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_leftover_cleanup_srcs)

set(LEFTOVER_CLEANUP_SRCS
    ${local_leftover_cleanup_srcs}
    PARENT_SCOPE
    )

set(LEFTOVER_CLEANUP_INCS
    ${CMAKE_CURRENT_SOURCE_DIR}
    PARENT_SCOPE
    )

if (DISABLE_OCI)
    list(REMOVE_ITEM
    local_leftover_cleanup_srcs 
    ${CMAKE_CURRENT_SOURCE_DIR}/oci_rootfs_clean.c
    )
endif()