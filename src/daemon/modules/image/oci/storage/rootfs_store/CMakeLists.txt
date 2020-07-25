# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_rootfs_store_srcs)

set(ROOTFS_STORE_SRCS
    ${local_rootfs_store_srcs}
    PARENT_SCOPE
    )
set(ROOTFS_STORE_INCS
    ${CMAKE_CURRENT_SOURCE_DIR}
    PARENT_SCOPE
    )
