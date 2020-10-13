# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} isula_network_srcs)

set(ISULA_NETWORK_SRCS
    ${isula_network_srcs}
    PARENT_SCOPE
    )
