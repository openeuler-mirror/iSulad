# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_storage_srcs)
add_subdirectory(image_store)
add_subdirectory(layer_store)
add_subdirectory(container_store)

set(STORAGE_SRCS
    ${local_storage_srcs}
    ${IMAGE_STORE_SRCS}
    ${LAYER_STORE_SRCS}
    ${CONTAINER_STORE_SRCS}
    PARENT_SCOPE
    )

set(STORAGE_INCS
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${IMAGE_STORE_INCS}
    ${LAYER_STORE_INCS}
    ${CONTAINER_STORE_INCS}
    PARENT_SCOPE
    )
