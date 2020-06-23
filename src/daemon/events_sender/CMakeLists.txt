# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_events_sender_srcs)

set(EVENTS_SENDER_SRCS
	${local_events_sender_srcs}
	PARENT_SCOPE
	)

set(EVENTS_SENDER_INCS
	${CMAKE_CURRENT_SOURCE_DIR}
	PARENT_SCOPE
	)
