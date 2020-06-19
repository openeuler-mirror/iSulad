# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_cpputils_srcs)

set(CPPUTILS_SRCS
    ${local_cpputils_srcs}
    PARENT_SCOPE
    )
set(CPPUTILS_INCS
    ${CMAKE_CURRENT_SOURCE_DIR}
    PARENT_SCOPE
    )

