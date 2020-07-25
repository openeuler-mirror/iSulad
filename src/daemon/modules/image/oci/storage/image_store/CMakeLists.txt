# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_image_store_srcs)

set(IMAGE_STORE_SRCS
    ${local_image_store_srcs}
    PARENT_SCOPE
    )
set(IMAGE_STORE_INCS
    ${CMAKE_CURRENT_SOURCE_DIR}
    PARENT_SCOPE
    )
