# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} cri_top_srcs)
set(local_cri_srcs ${cri_top_srcs})
set(local_cri_incs ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/v1alpha)

add_subdirectory(websocket)
list(APPEND local_cri_srcs ${WEBSOCKET_SERVICE_SRCS})
list(APPEND local_cri_incs ${WEBSOCKET_SERVICE_INCS})

if (ENABLE_CRI_API_V1)
    add_subdirectory(v1)
    list(APPEND local_cri_incs ${CMAKE_CURRENT_SOURCE_DIR}/v1)
endif()
add_subdirectory(v1alpha)

set(CRI_SRCS ${local_cri_srcs} ${CRI_V1_SRCS} ${CRI_V1ALPHA_SRCS} PARENT_SCOPE)
set(CRI_INCS ${local_cri_incs} ${CRI_V1_INCS} ${CRI_V1ALPHA_INCS} PARENT_SCOPE)
