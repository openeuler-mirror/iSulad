# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} device_top_srcs)

add_subdirectory(cdi)

set(local_device_srcs
    ${device_top_srcs}
    ${CDI_SRCS}
    )

set(local_device_incs
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CDI_INCS}
    )

set(DEVICE_SRCS
    ${local_device_srcs}
    PARENT_SCOPE
    )
set(DEVICE_INCS
    ${local_device_incs}
    PARENT_SCOPE
    )