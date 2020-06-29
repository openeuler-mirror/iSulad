# get current directory sources files

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} common_top_srcs)

set(local_common_srcs
    ${common_top_srcs}
    )

set(local_common_incs
    ${CMAKE_CURRENT_SOURCE_DIR}
    )

set(COMMON_SRCS
    ${local_common_srcs}
    PARENT_SCOPE
    )
set(COMMON_INCS
    ${local_common_incs}
    PARENT_SCOPE
    )


