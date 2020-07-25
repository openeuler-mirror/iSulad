# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} plugin_top_srcs)

set(local_plugin_srcs
    ${plugin_top_srcs}
    )

set(local_plugin_incs
    ${CMAKE_CURRENT_SOURCE_DIR}
    )

set(PLUGIN_SRCS
    ${local_plugin_srcs}
    PARENT_SCOPE
    )
set(PLUGIN_INCS
    ${local_plugin_incs}
    PARENT_SCOPE
    )
