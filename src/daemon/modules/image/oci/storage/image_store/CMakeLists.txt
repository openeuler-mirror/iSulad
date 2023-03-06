# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_image_store_srcs)
IF (NOT ENABLE_REMOTE_LAYER_STORE)
list(REMOVE_ITEM local_image_store_srcs "${CMAKE_CURRENT_SOURCE_DIR}/image_remote_impl.c")
ENDIF()

set(IMAGE_STORE_SRCS
    ${local_image_store_srcs}
    PARENT_SCOPE
    )
set(IMAGE_STORE_INCS
    ${CMAKE_CURRENT_SOURCE_DIR}
    PARENT_SCOPE
    )
