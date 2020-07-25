# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_service_srcs)

set(SERVICE_SRCS
	${local_service_srcs}
	PARENT_SCOPE
	)

set(SERVICE_INCS
	${CMAKE_CURRENT_SOURCE_DIR}
	PARENT_SCOPE
	)
