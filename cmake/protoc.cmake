set(PROTOS_PATH ${CMAKE_CURRENT_SOURCE_DIR}/src/api/services)

set(GRPC_OUT_PRE_PATH ${CMAKE_BINARY_DIR}/grpc)
set(CONTAINER_PROTOS_OUT_PATH ${GRPC_OUT_PRE_PATH}/src/api/services/containers)
set(IMAGE_PROTOS_OUT_PATH ${GRPC_OUT_PRE_PATH}/src/api/services/images)
set(VOLUME_PROTOS_OUT_PATH ${GRPC_OUT_PRE_PATH}/src/api/services/volumes)
set(CRI_PROTOS_OUT_PATH ${GRPC_OUT_PRE_PATH}/src/api/services/cri)
set(IMAGE_SERVICE_PROTOS_OUT_PATH ${GRPC_OUT_PRE_PATH}/src/api/image_client)

if (GRPC_CONNECTOR)
    message("---------------Generate GRPC proto-----------------------")
    execute_process(COMMAND mkdir -p ${CONTAINER_PROTOS_OUT_PATH})
    execute_process(COMMAND mkdir -p ${IMAGE_PROTOS_OUT_PATH})
    execute_process(COMMAND mkdir -p ${VOLUME_PROTOS_OUT_PATH})
    execute_process(COMMAND mkdir -p ${CRI_PROTOS_OUT_PATH})
    execute_process(COMMAND ${CMD_PROTOC} -I ${PROTOS_PATH}/containers --cpp_out=${CONTAINER_PROTOS_OUT_PATH} 
        ${PROTOS_PATH}/containers/container.proto ERROR_VARIABLE containers_err)
    if (containers_err)
        message("Parse containers.proto failed: ")
        message(FATAL_ERROR ${containers_err})
    endif()

    execute_process(COMMAND ${CMD_PROTOC} -I ${PROTOS_PATH}/containers --grpc_out=${CONTAINER_PROTOS_OUT_PATH} --plugin=protoc-gen-grpc=${CMD_GRPC_CPP_PLUGIN} ${PROTOS_PATH}/containers/container.proto ERROR_VARIABLE containers_err)
    if (containers_err)
        message("Parse containers.proto plugin failed: ")
        message(FATAL_ERROR ${containers_err})
    endif()

    execute_process(COMMAND ${CMD_PROTOC} -I ${PROTOS_PATH}/images --cpp_out=${IMAGE_PROTOS_OUT_PATH} ${PROTOS_PATH}/images/images.proto ERROR_VARIABLE images_err)
    if (images_err)
        message("Parse images.proto failed: ")
        message(FATAL_ERROR ${images_err})
    endif()

    execute_process(COMMAND ${CMD_PROTOC} -I ${PROTOS_PATH}/images --grpc_out=${IMAGE_PROTOS_OUT_PATH} --plugin=protoc-gen-grpc=${CMD_GRPC_CPP_PLUGIN} ${PROTOS_PATH}/images/images.proto ERROR_VARIABLE images_err)
    if (images_err)
        message("Parse images.proto plugin failed: ")
        message(FATAL_ERROR ${images_err})
    endif()

    execute_process(COMMAND ${CMD_PROTOC} -I ${PROTOS_PATH}/volumes --cpp_out=${VOLUME_PROTOS_OUT_PATH} ${PROTOS_PATH}/volumes/volumes.proto ERROR_VARIABLE volumes_err)
    if (volumes_err)
        message("Parse volumes.proto failed: ")
        message(FATAL_ERROR ${volumes_err})
    endif()

    execute_process(COMMAND ${CMD_PROTOC} -I ${PROTOS_PATH}/volumes --grpc_out=${VOLUME_PROTOS_OUT_PATH} --plugin=protoc-gen-grpc=${CMD_GRPC_CPP_PLUGIN} ${PROTOS_PATH}/volumes/volumes.proto ERROR_VARIABLE volumes_err)
    if (volumes_err)
        message("Parse volumes.proto plugin failed: ")
        message(FATAL_ERROR ${volumes_err})
    endif()

    execute_process(COMMAND ${CMD_PROTOC} -I ${PROTOS_PATH}/cri --cpp_out=${CRI_PROTOS_OUT_PATH} ${PROTOS_PATH}/cri/api.proto 
        ERROR_VARIABLE cri_err)
    if (cri_err)
        message("Parse cri.proto failed: ")
        message(FATAL_ERROR ${cri_err})
    endif()

    execute_process(COMMAND ${CMD_PROTOC} -I ${PROTOS_PATH}/cri --grpc_out=${CRI_PROTOS_OUT_PATH} 
        --plugin=protoc-gen-grpc=${CMD_GRPC_CPP_PLUGIN} ${PROTOS_PATH}/cri/api.proto ERROR_VARIABLE cri_err)
    if (cri_err)
        message("Parse cri.proto plugin failed: ")
        message(FATAL_ERROR ${cri_err})
    endif()
endif()

