# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} comm_srcs)

add_subdirectory(lcrc)
set(LCRC_SRCS ${comm_srcs} ${CMD_LCRC_SRCS} PARENT_SCOPE)
set(LCRC_INCS ${CMAKE_CURRENT_SOURCE_DIR} ${CMD_LCRC_INCS} PARENT_SCOPE)

add_subdirectory(lcrd)
set(LCRD_SRCS ${comm_srcs} ${CMD_LCRD_SRCS} PARENT_SCOPE)
set(LCRD_INCS ${CMAKE_CURRENT_SOURCE_DIR} ${CMD_LCRD_INCS} PARENT_SCOPE)
