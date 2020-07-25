# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_quota_srcs)

set(QUOTA_SRCS
    ${local_quota_srcs}
    PARENT_SCOPE
    )
