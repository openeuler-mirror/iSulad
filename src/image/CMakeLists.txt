# get current directory sources files

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} image_top_srcs)
add_subdirectory(external)

set(local_image_srcs
    ${image_top_srcs}
    ${EXTERNAL_SRCS}
    )

set(local_image_incs
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/external
    )

if (ENABLE_OCI_IMAGE)
    add_subdirectory(oci)
    list(APPEND local_image_srcs
	    ${OCI_SRCS}
        )
    list(APPEND local_image_incs
	    ${OCI_INCS}
        )
endif()

if (ENABLE_EMBEDDED_IMAGE)
    add_subdirectory(embedded)
    list(APPEND local_image_srcs
        ${EMBEDDED_SRCS}
        )
    list(APPEND local_image_incs
        ${EMBEDDED_INCS}
        )
endif()

set(IMAGE_SRCS
    ${local_image_srcs}
    PARENT_SCOPE
    )
set(IMAGE_INCS
    ${local_image_incs}
    PARENT_SCOPE
    )
