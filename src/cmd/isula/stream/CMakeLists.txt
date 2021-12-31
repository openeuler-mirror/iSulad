# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_isula_stream_srcs)

# use a separate micro defination for libarchive
if (DISABLE_OCI)
    list(REMOVE_ITEM local_isula_stream_srcs
        ${CMAKE_CURRENT_SOURCE_DIR}/cp.c
        )
endif()

set(ISULA_STREAM_SRCS
    ${local_isula_stream_srcs}
    PARENT_SCOPE
    )
