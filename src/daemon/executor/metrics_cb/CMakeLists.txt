# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_metrics_srcs)

set(METRICS_CB_SRCS
	${local_metrics_srcs}
	PARENT_SCOPE
	)

set(METRICS_CB_INCS
	${CMAKE_CURRENT_SOURCE_DIR}
	PARENT_SCOPE
	)
