# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/ executor_top_srcs)
set(local_executor_srcs ${executor_top_srcs})
set(local_executor_incs ${CMAKE_CURRENT_SOURCE_DIR})

add_subdirectory(container_cb)
list(APPEND local_executor_srcs ${CONTAINER_CB_SRCS})
list(APPEND local_executor_incs ${CONTAINER_CB_INCS})

add_subdirectory(image_cb)
list(APPEND local_executor_srcs ${IMAGE_CB_SRCS})
list(APPEND local_executor_incs ${IMAGE_CB_INCS})

add_subdirectory(volume_cb)
list(APPEND local_executor_srcs ${VOLUME_CB_SRCS})
list(APPEND local_executor_incs ${VOLUME_CB_INCS})

set(EXECUTOR_SRCS
    ${local_executor_srcs}
    PARENT_SCOPE
    )
set(EXECUTOR_INCS
    ${local_executor_incs}
    PARENT_SCOPE
    )
