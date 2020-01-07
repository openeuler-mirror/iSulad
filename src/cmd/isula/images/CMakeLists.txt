# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} isula_images_srcs)

set(ISULA_IMAGES_SRCS
    ${isula_images_srcs}
    PARENT_SCOPE
    )
