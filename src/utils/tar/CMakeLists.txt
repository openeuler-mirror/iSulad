# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_tar_srcs)

if (DISABLE_OCI)
    list(REMOVE_ITEM local_tar_srcs
        ${CMAKE_CURRENT_SOURCE_DIR}/util_archive.c
        ${CMAKE_CURRENT_SOURCE_DIR}/isulad_tar.c
        )
endif()

set(TAR_SRCS
    ${local_tar_srcs}
    PARENT_SCOPE
    )
set(TAR_INCS
    ${CMAKE_CURRENT_SOURCE_DIR}
    PARENT_SCOPE
    )

