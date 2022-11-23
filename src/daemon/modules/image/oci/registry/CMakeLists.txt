# get current directory sources files

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} image_registry_srcs)

if(NOT ENABLE_IMAGE_SEARCH)
    list(REMOVE_ITEM image_registry_srcs "${CMAKE_CURRENT_SOURCE_DIR}/registry_apiv1.c")
endif()

set(IMAGE_SRCS
    ${image_registry_srcs}
    PARENT_SCOPE
    )
