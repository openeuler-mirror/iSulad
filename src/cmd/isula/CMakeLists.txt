# get current directory sources files
add_subdirectory(base)
add_subdirectory(information)
add_subdirectory(extend)
add_subdirectory(stream)
add_subdirectory(images)
add_subdirectory(volume)
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} isula_srcs)

set(CMD_ISULA_SRCS
    ${isula_srcs}
    ${ISULA_BASE_SRCS}
    ${ISULA_EXTEND_SRCS}
    ${ISULA_IMAGES_SRCS}
    ${ISULA_VOLUME_SRCS}
    ${ISULA_INFORMATION_SRCS}
    ${ISULA_STREAM_SRCS}
    PARENT_SCOPE
    )

set(CMD_ISULA_INCS
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/base
    ${CMAKE_CURRENT_SOURCE_DIR}/extend
    ${CMAKE_CURRENT_SOURCE_DIR}/images
    ${CMAKE_CURRENT_SOURCE_DIR}/volume
    ${CMAKE_CURRENT_SOURCE_DIR}/information
    ${CMAKE_CURRENT_SOURCE_DIR}/stream
    PARENT_SCOPE
    )
