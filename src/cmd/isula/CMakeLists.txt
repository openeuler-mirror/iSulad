# get current directory sources files
add_subdirectory(base)
add_subdirectory(information)
add_subdirectory(extend)
add_subdirectory(stream)
add_subdirectory(images)
add_subdirectory(volume)
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} isula_srcs)

set(local_cmd_isula_srcs
    ${isula_srcs}
    ${ISULA_BASE_SRCS}
    ${ISULA_EXTEND_SRCS}
    ${ISULA_IMAGES_SRCS}
    ${ISULA_VOLUME_SRCS}
    ${ISULA_INFORMATION_SRCS}
    ${ISULA_STREAM_SRCS}
    )

set(local_cmd_isula_incs
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/base
    ${CMAKE_CURRENT_SOURCE_DIR}/extend
    ${CMAKE_CURRENT_SOURCE_DIR}/images
    ${CMAKE_CURRENT_SOURCE_DIR}/volume
    ${CMAKE_CURRENT_SOURCE_DIR}/information
    ${CMAKE_CURRENT_SOURCE_DIR}/stream
    )

if(ENABLE_NATIVE_NETWORK)
add_subdirectory(network)
list(APPEND local_cmd_isula_srcs ${ISULA_NETWORK_SRCS})
list(APPEND local_cmd_isula_incs ${CMAKE_CURRENT_SOURCE_DIR}/network)
endif(ENABLE_NATIVE_NETWORK)

set(CMD_ISULA_SRCS ${local_cmd_isula_srcs} PARENT_SCOPE)
set(CMD_ISULA_INCS ${local_cmd_isula_incs} PARENT_SCOPE)