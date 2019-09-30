# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_cri_srcs)

set(CRI_SRCS
    ${local_cri_srcs}
    PARENT_SCOPE
    )
