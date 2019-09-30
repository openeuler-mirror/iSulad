# get current directory sources files
add_subdirectory(service)
set(WEBSOCKET_SERVICE_SRCS ${WB_SERVICE_SRCS} PARENT_SCOPE)
set(WEBSOCKET_SERVICE_INCS ${WB_SERVICE_INCS} PARENT_SCOPE)
