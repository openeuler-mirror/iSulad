# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_storage_srcs)
add_subdirectory(image_store)
add_subdirectory(layer_store)
add_subdirectory(rootfs_store)
IF (ENABLE_REMOTE_LAYER_STORE)
add_subdirectory(remote_layer_support)
ENDIF()


set(STORAGE_SRCS
    ${local_storage_srcs}
    ${IMAGE_STORE_SRCS}
    ${LAYER_STORE_SRCS}
    ${ROOTFS_STORE_SRCS}
    ${REMOTE_LAYER_SUPPORT_SRCS}
    PARENT_SCOPE
    )

set(STORAGE_INCS
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${IMAGE_STORE_INCS}
    ${LAYER_STORE_INCS}
    ${ROOTFS_STORE_INCS}
    ${REMOTE_LAYER_SUPPORT_INCS}
    PARENT_SCOPE
    )
