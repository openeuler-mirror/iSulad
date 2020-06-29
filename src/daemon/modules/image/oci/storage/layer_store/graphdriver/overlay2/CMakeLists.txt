# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_overlay2_srcs)

set(OVERLAY2_SRCS
    ${local_overlay2_srcs}
    PARENT_SCOPE
    )
