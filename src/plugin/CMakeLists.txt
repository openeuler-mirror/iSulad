# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_plugin_srcs)

set(PLUGIN_SRCS
    ${local_plugin_srcs}
    PARENT_SCOPE
    )
