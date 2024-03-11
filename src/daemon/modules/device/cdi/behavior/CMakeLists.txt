aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} behavior_top_srcs)
add_subdirectory(parser)

set(BEHAVIOR_SRCS
    ${behavior_top_srcs}
    ${PARSER_SRCS}
    PARENT_SCOPE
    )
set(BEHAVIOR_INCS
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/parser/
    PARENT_SCOPE
    )
