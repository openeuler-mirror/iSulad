# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} isulad_shim_srcs)

set(CMD_ISULAD_SHIM_SRCS
    ${isulad_shim_srcs}
    PARENT_SCOPE
    )

set(CMD_ISULAD_SHIM_INCS
    ${CMAKE_CURRENT_SOURCE_DIR}
    PARENT_SCOPE
    )
