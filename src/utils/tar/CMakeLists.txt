# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_tar_srcs)

set(TAR_SRCS
    ${local_tar_srcs}
    PARENT_SCOPE
    )
set(TAR_INCS
    ${CMAKE_CURRENT_SOURCE_DIR}
    PARENT_SCOPE
    )

