# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_metrics_service_srcs)

set(METRICS_SERVICE_SRCS
    ${local_metrics_service_srcs}
    PARENT_SCOPE
    )
set(METRICS_SERVICE_INCS
    ${CMAKE_CURRENT_SOURCE_DIR}
    PARENT_SCOPE
    )