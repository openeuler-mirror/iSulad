# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_oci_srcs)
add_subdirectory(storage)
add_subdirectory(registry)

set(OCI_SRCS
    ${STORAGE_SRCS}
    ${local_oci_srcs}
    ${IMAGE_SRCS}
    PARENT_SCOPE
    )

set(OCI_INCS
    ${STORAGE_INCS}
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/registry
    PARENT_SCOPE
    )
