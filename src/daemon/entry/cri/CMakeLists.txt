# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} cri_top_srcs)
set(local_cri_srcs ${cri_top_srcs})
set(local_cri_incs ${CMAKE_CURRENT_SOURCE_DIR})

add_subdirectory(websocket)
list(APPEND local_cri_srcs ${WEBSOCKET_SERVICE_SRCS})
list(APPEND local_cri_incs ${WEBSOCKET_SERVICE_INCS})

set(CRI_SRCS ${local_cri_srcs} PARENT_SCOPE)
set(CRI_INCS ${local_cri_incs} PARENT_SCOPE)

