# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_oci_srcs)

set(OCI_SRCS
    ${local_oci_srcs}
    PARENT_SCOPE
    )

set(OCI_INCS
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/remote
    PARENT_SCOPE
    )
