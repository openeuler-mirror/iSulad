# get current directory sources files
add_subdirectory(base)
add_subdirectory(information)
add_subdirectory(extend)
add_subdirectory(stream)
add_subdirectory(images)
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} lcrc_srcs)

set(CMD_LCRC_SRCS
    ${lcrc_srcs}
    ${LCRC_BASE_SRCS}
    ${LCRC_EXTEND_SRCS}
    ${LCRC_IMAGES_SRCS}
    ${LCRC_INFORMATION_SRCS}
    ${LCRC_STREAM_SRCS}
    PARENT_SCOPE
    )

set(CMD_LCRC_INCS
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/base
    ${CMAKE_CURRENT_SOURCE_DIR}/extend
    ${CMAKE_CURRENT_SOURCE_DIR}/images
    ${CMAKE_CURRENT_SOURCE_DIR}/information
    ${CMAKE_CURRENT_SOURCE_DIR}/stream
    PARENT_SCOPE
    )
