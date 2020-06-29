# get current directory sources files

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} engines_top_srcs)
add_subdirectory(lcr)

set(ENGINES_SRCS
    ${engines_top_srcs}
    ${LCR_SRCS}
    PARENT_SCOPE
    )
set(ENGINES_INCS
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${LCR_INCS}
    PARENT_SCOPE
    )
