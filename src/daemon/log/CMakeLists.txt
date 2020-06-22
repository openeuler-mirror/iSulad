# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_log_gather_srcs)

set(LOG_GATHER_SRCS
    	${local_log_gather_srcs}
	PARENT_SCOPE
	)

set(LOG_GATHER_INCS
	${CMAKE_CURRENT_SOURCE_DIR}
    	PARENT_SCOPE
	)
