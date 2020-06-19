# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_spec_srcs)

set(SPEC_SRCS
    ${local_spec_srcs}
    PARENT_SCOPE
    )
