# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_external_srcs)

set(EXTERNAL_SRCS
    ${local_external_srcs}
    PARENT_SCOPE
    )
