# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_shim_srcs)

set(SHIM_SRCS
    ${local_shim_srcs}
    PARENT_SCOPE
    )
