# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_image_srcs)

set(IMAGE_SRCS
    ${local_image_srcs}
    PARENT_SCOPE
    )
