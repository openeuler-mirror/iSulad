# get current directory sources files

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} engines_top_srcs)
set(ENGINES_SRCS
    ${engines_top_srcs}
    PARENT_SCOPE
    )
set(ENGINES_INCS
    ${CMAKE_CURRENT_SOURCE_DIR}
    PARENT_SCOPE
    )
