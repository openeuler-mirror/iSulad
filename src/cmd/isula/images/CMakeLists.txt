# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} isula_images_srcs)

if(NOT ENABLE_IMAGE_SEARCH)
    list(REMOVE_ITEM isula_images_srcs "${CMAKE_CURRENT_SOURCE_DIR}/search.c")
endif()

set(ISULA_IMAGES_SRCS
    ${isula_images_srcs}
    PARENT_SCOPE
    )
