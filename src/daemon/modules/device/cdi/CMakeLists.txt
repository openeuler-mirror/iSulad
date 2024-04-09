aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} cdi_top_srcs)
add_subdirectory(behavior)

set(CDI_SRCS
    ${cdi_top_srcs}
    ${BEHAVIOR_SRCS}
    PARENT_SCOPE
    )
set(CDI_INCS
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${BEHAVIOR_INCS}
    PARENT_SCOPE
    )
