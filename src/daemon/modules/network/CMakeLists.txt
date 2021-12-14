aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} topsrcs)

add_subdirectory(cni_operator)
add_subdirectory(cri)


if (ENABLE_NATIVE_NETWORK)
add_subdirectory(native)
endif()

set(NETWORK_SRCS
    ${topsrcs}
    ${CNI_OPERATOR_SRCS}
    ${CRI_NET_SRCS}
    ${NATIVE_NET_SRCS}
    PARENT_SCOPE
    )
set(NETWORK_INCS
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CNI_OPERATOR_INCS}
    ${CRI_NET_INCS}
    ${NATIVE_NET_INCS}
    PARENT_SCOPE
    )
