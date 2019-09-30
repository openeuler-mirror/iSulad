# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} config_srcs)

set(CONFIG_SRCS
    ${config_srcs}
    PARENT_SCOPE
    )
