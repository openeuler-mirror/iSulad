# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} sandbox_controller_sandboxer_client_srcs)
aux_source_directory(${CMAKE_BINARY_DIR}/grpc/src/api/services/sandbox grpc_sandbox_api_srcs)
aux_source_directory(${CMAKE_BINARY_DIR}/grpc/src/api/services/sandbox/google/protobuf grpc_sandbox_google_protobuf_api_srcs)
aux_source_directory(${CMAKE_BINARY_DIR}/grpc/src/api/services/sandbox/sandbox/types sandbox_type_srcs)


set(CONTROLLER_SANDBOXER_CLIENT_SRCS
    ${sandbox_controller_sandboxer_client_srcs}
    ${grpc_sandbox_api_srcs}
    ${grpc_sandbox_google_protobuf_api_srcs}
    ${sandbox_type_srcs}
    PARENT_SCOPE
    )

set(CONTROLLER_SANDBOXER_CLIENT_INCS
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_BINARY_DIR}/grpc/src/api/services/sandbox
    PARENT_SCOPE
    )
