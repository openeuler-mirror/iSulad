# get current directory sources files

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} utils_top_srcs)
add_subdirectory(console)
add_subdirectory(cutils)
add_subdirectory(sha256)
add_subdirectory(tar)
add_subdirectory(http)
add_subdirectory(buffer)

set(local_utils_srcs
    ${utils_top_srcs}
    ${TAR_SRCS}
    ${SHA256_SRCS}
    ${CUTILS_SRCS}
    ${CONSOLE_SRCS}
    ${BUFFER_SRCS}
    )

set(local_utils_incs
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${TAR_INCS}
    ${SHA256_INCS}
    ${CUTILS_INCS}
    ${CONSOLE_INCS}
    ${BUFFER_INCS}
    )

if (GRPC_CONNECTOR)
        add_subdirectory(cpputils)
        list(APPEND local_utils_srcs ${CPPUTILS_SRCS})
        list(APPEND local_utils_incs ${CPPUTILS_INCS})
else()
        list(APPEND local_utils_incs ${CMAKE_CURRENT_SOURCE_DIR}/../api/services/containers/rest
                ${CMAKE_CURRENT_SOURCE_DIR}/../api/services/images/rest
                ${CMAKE_CURRENT_SOURCE_DIR}/../api/services/network/rest)

endif()

set(UTILS_SRCS
    ${local_utils_srcs}
    PARENT_SCOPE
    )
set(UTILS_INCS
    ${local_utils_incs}
    PARENT_SCOPE
    )


