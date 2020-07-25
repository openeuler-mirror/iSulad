# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_snapshot_srcs)

set(SNAPSHOT_SRCS
    ${local_snapshot_srcs}
    PARENT_SCOPE
    )
