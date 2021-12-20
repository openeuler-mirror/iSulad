aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} topsrcs)

add_subdirectory(libcni)

set(CNI_OPERATOR_SRCS
    ${topsrcs}
    ${LIB_CNI_SRCS}
    PARENT_SCOPE
    )
set(CNI_OPERATOR_INCS
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${LIB_CNI_INCS}
    PARENT_SCOPE
    )
