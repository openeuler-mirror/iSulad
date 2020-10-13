# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_network_cb_srcs)

set(NETWORK_CB_SRCS
	${local_network_cb_srcs}
	PARENT_SCOPE
	)

set(NETWORK_CB_INCS
	${CMAKE_CURRENT_SOURCE_DIR}
	PARENT_SCOPE
	)
