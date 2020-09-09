aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} topsrcs)

add_subdirectory(cni)

set(NETWORK_SRCS
    ${topsrcs}
    ${NETWORK_SRCS}
    PARENT_SCOPE
    )
set(NETWORK_INCS
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${NETWORK_INCS}
    PARENT_SCOPE
    )
