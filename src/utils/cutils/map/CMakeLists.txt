# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_map_srcs)

set(MAP_SRCS
    ${local_map_srcs}
    PARENT_SCOPE
    )

set(MAP_INCS
    ${CMAKE_CURRENT_SOURCE_DIR}
    PARENT_SCOPE
    )

