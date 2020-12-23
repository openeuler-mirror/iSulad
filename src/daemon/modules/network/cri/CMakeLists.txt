aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} topsrcs)

set(CRI_NET_SRCS
    ${topsrcs}
    PARENT_SCOPE
    )
set(CRI_NET_INCS
    ${CMAKE_CURRENT_SOURCE_DIR}
    PARENT_SCOPE
    )
