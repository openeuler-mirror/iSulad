# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_manager_srcs)

set(MANAGER_SRCS
	${local_manager_srcs}
	PARENT_SCOPE
	)

set(MANAGER_INCS
	${CMAKE_CURRENT_SOURCE_DIR}
	PARENT_SCOPE
	)
