# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_db_srcs)

set(DB_SRCS
    ${local_db_srcs}
    PARENT_SCOPE
    )
