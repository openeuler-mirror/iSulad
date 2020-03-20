# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/ services_top_srcs)
set(local_services_srcs ${services_top_srcs})
set(local_services_incs ${CMAKE_CURRENT_SOURCE_DIR})
if (GRPC_CONNECTOR)
		add_subdirectory(cri)
		list(APPEND local_services_srcs ${CRI_SRCS})
		list(APPEND local_services_incs ${CMAKE_CURRENT_SOURCE_DIR}/cri)
endif()
add_subdirectory(execution)
list(APPEND local_services_srcs ${EXECUTION_SRCS})
list(APPEND local_services_incs ${EXECUTION_INCS})

add_subdirectory(image)
list(APPEND local_services_srcs ${IMAGE_SRCS})
list(APPEND local_services_incs ${CMAKE_CURRENT_SOURCE_DIR}/image)

set(SERVICES_SRCS
    ${local_services_srcs}
    PARENT_SCOPE
    )
set(SERVICES_INCS
    ${local_services_incs}
    PARENT_SCOPE
    )
