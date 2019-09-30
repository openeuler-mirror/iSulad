# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} lcrc_images_srcs)

set(LCRC_IMAGES_SRCS
    ${lcrc_images_srcs}
    PARENT_SCOPE
    )
