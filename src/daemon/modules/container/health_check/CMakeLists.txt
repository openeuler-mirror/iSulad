# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_health_check_srcs)

set(HEALTH_CHECK_SRCS
	${local_health_check_srcs}
	PARENT_SCOPE
	)

set(HEALTH_CHECK_INCS
	${CMAKE_CURRENT_SOURCE_DIR}
	PARENT_SCOPE
	)
