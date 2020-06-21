# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/ callback_top_srcs)
set(local_callback_srcs ${callback_top_srcs})
set(local_callback_incs ${CMAKE_CURRENT_SOURCE_DIR})

add_subdirectory(container_cb)
list(APPEND local_callback_srcs ${CONTAINER_CB_SRCS})
list(APPEND local_callback_incs ${CONTAINER_CB_INCS})

add_subdirectory(image_cb)
list(APPEND local_callback_srcs ${IMAGE_CB_SRCS})
list(APPEND local_callback_incs ${IMAGE_CB_INCS})

set(CALLBACK_SRCS
    ${local_callback_srcs}
    PARENT_SCOPE
    )
set(CALLBACK_INCS
    ${local_callback_incs}
    PARENT_SCOPE
    )
