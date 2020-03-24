# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_oci_srcs)
add_subdirectory(storage)

set(OCI_SRCS
    ${STORAGE_SRCS}
    ${local_oci_srcs}
    PARENT_SCOPE
    )

set(OCI_INCS
    ${STORAGE_INCS}
    ${CMAKE_CURRENT_SOURCE_DIR}
    PARENT_SCOPE
    )
