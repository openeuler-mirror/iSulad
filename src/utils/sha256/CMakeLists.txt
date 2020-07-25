# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_sha256_srcs)

set(SHA256_SRCS
    ${local_sha256_srcs}
    PARENT_SCOPE
    )

set(SHA256_INCS
    ${CMAKE_CURRENT_SOURCE_DIR}
    PARENT_SCOPE
    )

