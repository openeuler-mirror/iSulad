# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_overlay2_srcs)
IF (NOT ENABLE_REMOTE_LAYER_STORE)
list(REMOVE_ITEM local_overlay2_srcs "${CMAKE_CURRENT_SOURCE_DIR}/overlay_remote_impl.c")
ENDIF()

set(OVERLAY2_SRCS
    ${local_overlay2_srcs}
    PARENT_SCOPE
    )
