aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} topsrcs)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/version)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/types)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/invoke)

set(LIB_CNI_SRCS
    ${topsrcs}
    ${VERSION_SRCS}
    ${TYPE_SRCS}
    ${INVOKE_SRCS}
    PARENT_SCOPE
    )
set(LIB_CNI_INCS
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/version/
    ${CMAKE_CURRENT_SOURCE_DIR}/types/
    ${CMAKE_CURRENT_SOURCE_DIR}/invoke/
    PARENT_SCOPE
    )
