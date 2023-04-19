# get current directory sources files

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} sandbox_controller_proxy_client_grpc_srcs)
aux_source_directory(${CMAKE_BINARY_DIR}/grpc/src/api/services/sandbox SANDBOX_API_SRC)
# aux_source_directory(${CMAKE_BINARY_DIR}/grpc/src/api/services/sandbox/gogoproto SANDBOX_GOGO_PROTO_API_SRC)
aux_source_directory(${CMAKE_BINARY_DIR}/grpc/src/api/services/sandbox/google/protobuf SANDBOX_GOOGLE_PROTOBUF_API_SRC)
aux_source_directory(${CMAKE_BINARY_DIR}/grpc/src/api/services/sandbox/github.com/containerd/containerd/api/types SANDBOX_CONTAINERD_TYPE_API_SRC)

set(local_sandbox_controller_proxy_client_grpc_srcs
    ${sandbox_controller_proxy_client_grpc_srcs}
    )

set(local_sandbox_controller_proxy_client_grpc_incs
    ${CMAKE_CURRENT_SOURCE_DIR}
    )

list(APPEND local_sandbox_controller_proxy_client_grpc_incs ${CMAKE_BINARY_DIR}/grpc/src/api/services/sandbox)

set(CONTROLLER_PROXY_CLIENT_GRPC_SRCS
    ${local_sandbox_controller_proxy_client_grpc_srcs}
    ${SANDBOX_API_SRC}
    ${SANDBOX_GOOGLE_PROTOBUF_API_SRC}
    ${SANDBOX_CONTAINERD_TYPE_API_SRC}
    PARENT_SCOPE
    )

set(CONTROLLER_PROXY_CLIENT_GRPC_INCS
    ${local_sandbox_controller_proxy_client_grpc_incs}
    PARENT_SCOPE
    )
