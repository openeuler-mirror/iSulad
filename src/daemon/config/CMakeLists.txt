# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/ config_top_srcs)
set(local_config_srcs ${config_top_srcs})
set(local_config_incs ${CMAKE_CURRENT_SOURCE_DIR})

set(CONFIG_SRCS
    ${local_config_srcs}
    PARENT_SCOPE
    )
set(CONFIG_INCS
    ${local_config_incs}
    PARENT_SCOPE
    )
