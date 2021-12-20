# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/ executor_top_srcs)
set(local_executor_srcs ${executor_top_srcs})
set(local_executor_incs ${CMAKE_CURRENT_SOURCE_DIR})

add_subdirectory(container_cb)
list(APPEND local_executor_srcs ${CONTAINER_CB_SRCS})
list(APPEND local_executor_incs ${CONTAINER_CB_INCS})
if(NOT ENABLE_NETWORK)
    list(REMOVE_ITEM local_executor_srcs "${CMAKE_CURRENT_SOURCE_DIR}/container_cb/execution_network.c")
    list(REMOVE_ITEM local_executor_incs "${CMAKE_CURRENT_SOURCE_DIR}/container_cb/execution_network.h")
endif()

add_subdirectory(image_cb)
list(APPEND local_executor_srcs ${IMAGE_CB_SRCS})
list(APPEND local_executor_incs ${IMAGE_CB_INCS})

add_subdirectory(volume_cb)
list(APPEND local_executor_srcs ${VOLUME_CB_SRCS})
list(APPEND local_executor_incs ${VOLUME_CB_INCS})

if (ENABLE_METRICS)
    add_subdirectory(metrics_cb)
    list(APPEND local_executor_srcs ${METRICS_CB_SRCS})
    list(APPEND local_executor_incs ${METRICS_CB_INCS})
endif()

if(ENABLE_NATIVE_NETWORK)
    add_subdirectory(network_cb)
    list(APPEND local_executor_srcs ${NETWORK_CB_SRCS})
    list(APPEND local_executor_incs ${NETWORK_CB_INCS})
endif()

set(EXECUTOR_SRCS
    ${local_executor_srcs}
    PARENT_SCOPE
    )
set(EXECUTOR_INCS
    ${local_executor_incs}
    PARENT_SCOPE
    )
