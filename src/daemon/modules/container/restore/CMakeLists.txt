# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_restore_srcs)

set(RESTORE_SRCS
	${local_restore_srcs}
	PARENT_SCOPE
	)

set(RESTORE_INCS
	${CMAKE_CURRENT_SOURCE_DIR}
	PARENT_SCOPE
	)
