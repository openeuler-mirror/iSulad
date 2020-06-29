# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_console_srcs)

set(CONSOLE_SRCS
    ${local_console_srcs}
    PARENT_SCOPE
    )

set(CONSOLE_INCS
    ${CMAKE_CURRENT_SOURCE_DIR}
    PARENT_SCOPE
    )
