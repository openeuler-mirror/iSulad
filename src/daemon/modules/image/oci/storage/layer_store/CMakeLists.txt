# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_layer_store_srcs)
IF (NOT ENABLE_REMOTE_LAYER_STORE)
list(REMOVE_ITEM local_layer_store_srcs "${CMAKE_CURRENT_SOURCE_DIR}/layer_remote_impl.c")
ENDIF()
add_subdirectory(graphdriver)

set(LAYER_STORE_SRCS
    ${local_layer_store_srcs}
    ${GRAPHDRIVER_SRCS}
    PARENT_SCOPE
    )

set(LAYER_STORE_INCS
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${GRAPHDRIVER_INCS}
    PARENT_SCOPE
    )
