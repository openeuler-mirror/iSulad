# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_cutils_srcs)
add_subdirectory(map)

if ((NOT ANDROID) AND (NOT MUSL))
    list(REMOVE_ITEM local_cutils_srcs "${CMAKE_CURRENT_SOURCE_DIR}/utils_pwgr.c")
endif()

set(CUTILS_SRCS
    ${local_cutils_srcs}
    ${MAP_SRCS}
    PARENT_SCOPE
    )

set(CUTILS_INCS
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${MAP_INCS}
    PARENT_SCOPE
    )


