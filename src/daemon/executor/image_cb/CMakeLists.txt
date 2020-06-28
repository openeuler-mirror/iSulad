# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_image_cb_srcs)

set(IMAGE_CB_SRCS
	${local_image_cb_srcs}
	PARENT_SCOPE
	)

set(IMAGE_CB_INCS
	${CMAKE_CURRENT_SOURCE_DIR}
	PARENT_SCOPE
	)
