# get current directory sources files

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} sandbox_top_srcs)

set(SANDBOX_SRCS
    ${sandbox_top_srcs}
    PARENT_SCOPE
    )
set(SANDBOX_INCS
    ${CMAKE_CURRENT_SOURCE_DIR}
    PARENT_SCOPE
    )
