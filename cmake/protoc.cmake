set(PROTOS_PATH ${CMAKE_CURRENT_SOURCE_DIR}/src/api/services)

set(GRPC_OUT_PRE_PATH ${CMAKE_BINARY_DIR}/grpc)
set(CONTAINER_PROTOS_OUT_PATH ${GRPC_OUT_PRE_PATH}/src/api/services/containers)
set(IMAGE_PROTOS_OUT_PATH ${GRPC_OUT_PRE_PATH}/src/api/services/images)
set(VOLUME_PROTOS_OUT_PATH ${GRPC_OUT_PRE_PATH}/src/api/services/volumes)
set(IMAGE_SERVICE_PROTOS_OUT_PATH ${GRPC_OUT_PRE_PATH}/src/api/image_client)

set(CRI_PROTOS_OUT_PATH ${GRPC_OUT_PRE_PATH}/src/api/services/cri)

if (ENABLE_NATIVE_NETWORK)
set(NETWORK_PROTOS_OUT_PATH ${GRPC_OUT_PRE_PATH}/src/api/services/network)
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
    execute_process(COMMAND mkdir -p ${CRI_PROTOS_OUT_PATH}/v1alpha)

    PROTOC_CPP_GEN(containers ${CONTAINER_PROTOS_OUT_PATH} ${PROTOS_PATH}/containers/container.proto)
    PROTOC_GRPC_GEN(containers ${CONTAINER_PROTOS_OUT_PATH} ${PROTOS_PATH}/containers/container.proto)

    PROTOC_CPP_GEN(images ${IMAGE_PROTOS_OUT_PATH} ${PROTOS_PATH}/images/images.proto)
    PROTOC_GRPC_GEN(images ${IMAGE_PROTOS_OUT_PATH} ${PROTOS_PATH}/images/images.proto)

    PROTOC_CPP_GEN(volumes ${VOLUME_PROTOS_OUT_PATH} ${PROTOS_PATH}/volumes/volumes.proto)
    PROTOC_GRPC_GEN(volumes ${VOLUME_PROTOS_OUT_PATH} ${PROTOS_PATH}/volumes/volumes.proto)

    # generator v1alpha cri proto for iSulad
    PROTOC_CPP_GEN(cri ${CRI_PROTOS_OUT_PATH} ${PROTOS_PATH}/cri/v1alpha/api.proto)
    PROTOC_GRPC_GEN(cri ${CRI_PROTOS_OUT_PATH} ${PROTOS_PATH}/cri/v1alpha/api.proto)
    PROTOC_CPP_GEN(cri ${CRI_PROTOS_OUT_PATH} ${PROTOS_PATH}/cri/gogo.proto)
    PROTOC_GRPC_GEN(cri ${CRI_PROTOS_OUT_PATH} ${PROTOS_PATH}/cri/gogo.proto)

    if (ENABLE_CRI_API_V1)
        execute_process(COMMAND mkdir -p ${CRI_PROTOS_OUT_PATH}/v1)
        # generator v1 cri proto for iSulad
        PROTOC_CPP_GEN(cri ${CRI_PROTOS_OUT_PATH} ${PROTOS_PATH}/cri/v1/api_v1.proto)
        PROTOC_GRPC_GEN(cri ${CRI_PROTOS_OUT_PATH} ${PROTOS_PATH}/cri/v1/api_v1.proto)
    endif()

    if (ENABLE_NATIVE_NETWORK)
        execute_process(COMMAND mkdir -p ${NETWORK_PROTOS_OUT_PATH})
        PROTOC_CPP_GEN(network ${NETWORK_PROTOS_OUT_PATH} ${PROTOS_PATH}/network/network.proto)
        PROTOC_GRPC_GEN(network ${NETWORK_PROTOS_OUT_PATH} ${PROTOS_PATH}/network/network.proto)
    endif()
endif()

