# get current directory sources files

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} image_registry_srcs)

set(IMAGE_SRCS
    ${image_registry_srcs}
    PARENT_SCOPE
    )
