# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} mailbox_top_srcs)

set(MAILBOX_SRCS
    ${mailbox_top_srcs}
    PARENT_SCOPE
    )
set(MAILBOX_INCS
    ${CMAKE_CURRENT_SOURCE_DIR}
    PARENT_SCOPE
    )