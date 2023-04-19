set(PROTOS_PATH ${CMAKE_CURRENT_SOURCE_DIR}/src/api/services)

set(GRPC_OUT_PRE_PATH ${CMAKE_BINARY_DIR}/grpc)
set(CONTAINER_PROTOS_OUT_PATH ${GRPC_OUT_PRE_PATH}/src/api/services/containers)
set(IMAGE_PROTOS_OUT_PATH ${GRPC_OUT_PRE_PATH}/src/api/services/images)
set(VOLUME_PROTOS_OUT_PATH ${GRPC_OUT_PRE_PATH}/src/api/services/volumes)
set(CRI_PROTOS_OUT_PATH ${GRPC_OUT_PRE_PATH}/src/api/services/cri)
set(IMAGE_SERVICE_PROTOS_OUT_PATH ${GRPC_OUT_PRE_PATH}/src/api/image_client)

if (ENABLE_NATIVE_NETWORK)
set(NETWORK_PROTOS_OUT_PATH ${GRPC_OUT_PRE_PATH}/src/api/services/network)
endif()

if (ENABLE_SANDBOX)
set(SANDBOX_PROTOS_OUT_PATH ${GRPC_OUT_PRE_PATH}/src/api/services/sandbox)
endif()

macro(PROTOC_CPP_GEN proto_name cpp_out_path proto_path)
    execute_process(COMMAND ${CMD_PROTOC} -I ${PROTOS_PATH}/${proto_name} --cpp_out=${cpp_out_path} ${proto_path} ERROR_VARIABLE cpp_err)
    if (cpp_err)
        message("Parse ${proto_path} failed: ")
        message(FATAL_ERROR ${cpp_err})
    endif()
endmacro(PROTOC_CPP_GEN)

macro(PROTOC_GRPC_GEN proto_name grpc_out_path proto_path)
    execute_process(COMMAND ${CMD_PROTOC} -I ${PROTOS_PATH}/${proto_name} --grpc_out=${grpc_out_path} --plugin=protoc-gen-grpc=${CMD_GRPC_CPP_PLUGIN} ${proto_path} ERROR_VARIABLE grpc_err)
    if (grpc_err)
        message("Parse ${proto_path} failed: ")
        message(FATAL_ERROR ${grpc_err})
    endif()
endmacro(PROTOC_GRPC_GEN)

if (GRPC_CONNECTOR)
    execute_process(COMMAND mkdir -p ${CONTAINER_PROTOS_OUT_PATH})
    execute_process(COMMAND mkdir -p ${IMAGE_PROTOS_OUT_PATH})
    execute_process(COMMAND mkdir -p ${VOLUME_PROTOS_OUT_PATH})
    execute_process(COMMAND mkdir -p ${CRI_PROTOS_OUT_PATH})

    PROTOC_CPP_GEN(containers ${CONTAINER_PROTOS_OUT_PATH} ${PROTOS_PATH}/containers/container.proto)
    PROTOC_GRPC_GEN(containers ${CONTAINER_PROTOS_OUT_PATH} ${PROTOS_PATH}/containers/container.proto)

    PROTOC_CPP_GEN(images ${IMAGE_PROTOS_OUT_PATH} ${PROTOS_PATH}/images/images.proto)
    PROTOC_GRPC_GEN(images ${IMAGE_PROTOS_OUT_PATH} ${PROTOS_PATH}/images/images.proto)

    PROTOC_CPP_GEN(volumes ${VOLUME_PROTOS_OUT_PATH} ${PROTOS_PATH}/volumes/volumes.proto)
    PROTOC_GRPC_GEN(volumes ${VOLUME_PROTOS_OUT_PATH} ${PROTOS_PATH}/volumes/volumes.proto)

    PROTOC_CPP_GEN(cri ${CRI_PROTOS_OUT_PATH} ${PROTOS_PATH}/cri/api.proto)
    PROTOC_GRPC_GEN(cri ${CRI_PROTOS_OUT_PATH} ${PROTOS_PATH}/cri/api.proto)

    PROTOC_CPP_GEN(cri ${CRI_PROTOS_OUT_PATH} ${PROTOS_PATH}/cri/gogo.proto)
    PROTOC_GRPC_GEN(cri ${CRI_PROTOS_OUT_PATH} ${PROTOS_PATH}/cri/gogo.proto)

    if (ENABLE_NATIVE_NETWORK)
        execute_process(COMMAND mkdir -p ${NETWORK_PROTOS_OUT_PATH})
        PROTOC_CPP_GEN(network ${NETWORK_PROTOS_OUT_PATH} ${PROTOS_PATH}/network/network.proto)
        PROTOC_GRPC_GEN(network ${NETWORK_PROTOS_OUT_PATH} ${PROTOS_PATH}/network/network.proto)
    endif()
endif()

if (ENABLE_SANDBOX)
    execute_process(COMMAND mkdir -p ${SANDBOX_PROTOS_OUT_PATH})
    PROTOC_CPP_GEN(sandbox ${SANDBOX_PROTOS_OUT_PATH} ${PROTOS_PATH}/sandbox/google/protobuf/any.proto)

    PROTOC_CPP_GEN(sandbox ${SANDBOX_PROTOS_OUT_PATH} ${PROTOS_PATH}/sandbox/google/protobuf/empty.proto)

    PROTOC_CPP_GEN(sandbox ${SANDBOX_PROTOS_OUT_PATH} ${PROTOS_PATH}/sandbox/google/protobuf/timestamp.proto)

    PROTOC_CPP_GEN(sandbox ${SANDBOX_PROTOS_OUT_PATH} ${PROTOS_PATH}/sandbox/github.com/containerd/containerd/api/types/sandbox.proto)

    PROTOC_CPP_GEN(sandbox ${SANDBOX_PROTOS_OUT_PATH} ${PROTOS_PATH}/sandbox/github.com/containerd/containerd/api/types/mount.proto)

    PROTOC_CPP_GEN(sandbox ${SANDBOX_PROTOS_OUT_PATH} ${PROTOS_PATH}/sandbox/github.com/containerd/containerd/api/types/platform.proto)

    PROTOC_CPP_GEN(sandbox ${SANDBOX_PROTOS_OUT_PATH} ${PROTOS_PATH}/sandbox/sandbox.proto)

    PROTOC_GRPC_GEN(sandbox ${SANDBOX_PROTOS_OUT_PATH} ${PROTOS_PATH}/sandbox/sandbox.proto)
endif()
