# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_embedded_srcs)
add_subdirectory(db)
add_subdirectory(snapshot)

set(EMBEDDED_SRCS
    ${local_embedded_srcs}
    ${DB_SRCS}
    ${SNAPSHOT_SRCS}
    PARENT_SCOPE
    )
set(EMBEDDED_INCS
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/db
    ${CMAKE_CURRENT_SOURCE_DIR}/snapshot
    PARENT_SCOPE
    )
