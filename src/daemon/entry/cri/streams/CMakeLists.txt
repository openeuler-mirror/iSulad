# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} cri_stream_srcs)

add_subdirectory(websocket)

set(STREAM_SERVICE_SRCS
    ${cri_stream_srcs}
    ${WB_SERVICE_SRCS}
    PARENT_SCOPE)

set(STREAM_SERVICE_INCS
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${WB_SERVICE_INCS}
    PARENT_SCOPE)
