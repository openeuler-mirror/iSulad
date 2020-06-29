# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_events_srcs)

set(EVENTS_SRCS
	${local_events_srcs}
	PARENT_SCOPE
	)

set(EVENTS_INCS
	${CMAKE_CURRENT_SOURCE_DIR}
	PARENT_SCOPE
	)
