aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} topsrcs)

set(NATIVE_NET_SRCS
    ${topsrcs}
    PARENT_SCOPE
    )
set(NATIVE_NET_INCS
    ${CMAKE_CURRENT_SOURCE_DIR}
    PARENT_SCOPE
    )
