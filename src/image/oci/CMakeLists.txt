# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_oci_srcs)
add_subdirectory(graphdriver)

set(OCI_SRCS
    ${local_oci_srcs}
    ${GRAPHDRIVER_SRCS}
    PARENT_SCOPE
    )

set(OCI_INCS
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${GRAPHDRIVER_INCS}
    PARENT_SCOPE
    )
