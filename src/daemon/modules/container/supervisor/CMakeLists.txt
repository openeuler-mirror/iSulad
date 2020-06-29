# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_supervisor_srcs)

set(SUPERVISOR_SRCS
	${local_supervisor_srcs}
	PARENT_SCOPE
	)

set(SUPERVISOR_INCS
	${CMAKE_CURRENT_SOURCE_DIR}
	PARENT_SCOPE
	)
