# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_srcs)

if (ENABLE_CRI_API_V1)
    add_subdirectory(v1)
endif()

add_subdirectory(v1alpha)

set(SERVICE_CRI_SRCS
    ${SERVICE_CRI_V1ALPHA_SRCS}
    ${SERVICE_CRI_V1_SRCS}
    ${local_srcs}
    PARENT_SCOPE
)

set(SERVICE_CRI_INCS
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/v1alpha
    ${CMAKE_CURRENT_SOURCE_DIR}/v1
    PARENT_SCOPE
)