# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} comm_srcs)

add_subdirectory(options)

add_subdirectory(isula)
set(ISULA_SRCS ${comm_srcs} ${OPT_SRCS} ${CMD_ISULA_SRCS} PARENT_SCOPE)
set(ISULA_INCS ${CMAKE_CURRENT_SOURCE_DIR} ${OPT_INCS} ${CMD_ISULA_INCS} PARENT_SCOPE)

add_subdirectory(isulad)
set(ISULAD_SRCS ${comm_srcs} ${OPT_SRCS} ${CMD_ISULAD_SRCS} PARENT_SCOPE)
set(ISULAD_INCS ${CMAKE_CURRENT_SOURCE_DIR} ${OPT_INCS} ${CMD_ISULAD_INCS} PARENT_SCOPE)

add_subdirectory(isulad-shim)
set(ISULAD_SHIM_SRCS  ${CMD_ISULAD_SHIM_SRCS} PARENT_SCOPE)
set(ISULAD_SHIM_INCS ${CMAKE_CURRENT_SOURCE_DIR} ${CMD_ISULAD_SHIM_INCS} PARENT_SCOPE)
