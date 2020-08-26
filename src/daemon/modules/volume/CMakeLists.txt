# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_volume_srcs)

set(VOLUME_SRCS
	${local_volume_srcs}
	PARENT_SCOPE
	)

set(VOLUME_INCS
	${CMAKE_CURRENT_SOURCE_DIR}
	PARENT_SCOPE
	)
